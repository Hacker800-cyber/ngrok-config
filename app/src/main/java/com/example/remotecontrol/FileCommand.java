package com.example.remotecontrol;

import android.util.Log;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * FileCommand - Secure File Upload/Download Operations
 *
 * यह class file transfer functionality implement करती है:
 * - Secure file upload (device → server)
 * - Secure file download (server → device)
 * - MIME type detection
 * - Progress tracking callback
 * - Error recovery with retry logic
 * - Path traversal attack prevention
 *
 * Usage:
 *   FileCommand cmd = new FileCommand(securityManager);
 *   registry.register(cmd);
 *
 *   // Upload: params = {"action":"upload","path":"/sdcard/photo.jpg","url":"https://..."}
 *   // Download: params = {"action":"download","url":"https://...","dest":"/sdcard/file.txt"}
 */
public class FileCommand extends CommandBase {

    private static final String TAG = "FileCommand";

    // Maximum file size for upload (50 MB)
    private static final long MAX_FILE_SIZE_BYTES = 50L * 1024 * 1024;

    // Buffer size for stream copy
    private static final int BUFFER_SIZE = 8192;

    // HTTP timeout settings
    private static final int CONNECT_TIMEOUT_MS = 15_000;
    private static final int READ_TIMEOUT_MS    = 60_000;  // Larger for file transfers

    // Maximum retry attempts on transient errors
    private static final int MAX_RETRIES = 3;

    /**
     * Constructor
     */
    public FileCommand(SecurityManager securityManager) {
        super("file_operation", securityManager);
    }

    /**
     * doExecute() - "action" parameter के आधार पर upload या download करें
     *
     * Expected params:
     *   action  : "upload" | "download"
     *   Upload  : path (local file), url (destination)
     *   Download: url (source), dest (local destination path)
     */
    @Override
    protected String doExecute(JSONObject params) throws Exception {
        String action = params.optString("action", "").toLowerCase();

        switch (action) {
            case "upload":
                return handleUpload(params);
            case "download":
                return handleDownload(params);
            default:
                throw new IllegalArgumentException(
                        "Unknown file action: '" + action + "'. Use 'upload' or 'download'.");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Upload
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * handleUpload() - device की local file को server पर upload करें
     *
     * @param params  {"path":"...", "url":"...", "mime":"..."}
     */
    private String handleUpload(JSONObject params) throws Exception {
        String localPath = params.optString("path", "").trim();
        String uploadUrl = params.optString("url", "").trim();
        String mimeType  = params.optString("mime", "application/octet-stream").trim();

        // Validate inputs
        if (localPath.isEmpty()) throw new IllegalArgumentException("'path' is required for upload");
        if (uploadUrl.isEmpty()) throw new IllegalArgumentException("'url' is required for upload");

        // Security: path traversal attack prevention
        File file = new File(localPath).getCanonicalFile();
        validateFilePath(file);

        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("File not found: " + localPath);
        }

        long fileSize = file.length();
        if (fileSize > MAX_FILE_SIZE_BYTES) {
            throw new IllegalArgumentException(
                    "File too large: " + fileSize + " bytes (max " + MAX_FILE_SIZE_BYTES + ")");
        }

        // Auto-detect MIME type if not provided
        if ("application/octet-stream".equals(mimeType)) {
            mimeType = detectMimeType(localPath);
        }

        logInfo("Uploading " + file.getName() + " (" + fileSize + " bytes) to " + uploadUrl);

        // Retry loop for transient errors
        Exception lastError = null;
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                String result = performUpload(file, uploadUrl, mimeType,
                        new ProgressCallback() {
                            @Override
                            public void onProgress(long bytesTransferred, long totalBytes) {
                                int pct = (int) (bytesTransferred * 100 / totalBytes);
                                logDebug("Upload progress: " + pct + "%");
                            }
                        });
                logInfo("Upload successful on attempt " + attempt);
                return result;
            } catch (java.net.SocketTimeoutException e) {
                lastError = e;
                Log.w(TAG, "Upload attempt " + attempt + " timed out, retrying...");
                Thread.sleep(1000L * attempt); // Backoff between retries
            }
        }
        throw new Exception("Upload failed after " + MAX_RETRIES + " attempts: "
                + lastError.getMessage());
    }

    /**
     * performUpload() - actual HTTP PUT/POST upload
     */
    private String performUpload(File file, String uploadUrl, String mimeType,
                                  ProgressCallback progressCallback) throws Exception {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(uploadUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("PUT");
            conn.setDoOutput(true);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", mimeType);
            conn.setRequestProperty("Content-Length", String.valueOf(file.length()));
            conn.setFixedLengthStreamingMode(file.length());

            // Stream file to server
            OutputStream out = conn.getOutputStream();
            FileInputStream fis = new FileInputStream(file);
            byte[] buffer = new byte[BUFFER_SIZE];
            long totalSent = 0;
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
                totalSent += bytesRead;
                if (progressCallback != null) {
                    progressCallback.onProgress(totalSent, file.length());
                }
            }
            fis.close();
            out.flush();
            out.close();

            int responseCode = conn.getResponseCode();
            if (responseCode < 200 || responseCode >= 300) {
                throw new Exception("Server returned HTTP " + responseCode);
            }

            JSONObject result = new JSONObject();
            result.put("file", file.getName());
            result.put("size_bytes", file.length());
            result.put("mime_type", mimeType);
            result.put("http_status", responseCode);
            return result.toString();

        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Download
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * handleDownload() - server से file download करके device पर save करें
     *
     * @param params  {"url":"...", "dest":"..."}
     */
    private String handleDownload(JSONObject params) throws Exception {
        String downloadUrl = params.optString("url", "").trim();
        String destPath    = params.optString("dest", "").trim();

        if (downloadUrl.isEmpty()) throw new IllegalArgumentException("'url' is required for download");
        if (destPath.isEmpty())    throw new IllegalArgumentException("'dest' is required for download");

        // Security: validate destination path
        File destFile = new File(destPath).getCanonicalFile();
        validateFilePath(destFile);

        // Ensure parent directory exists
        File parentDir = destFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            if (!parentDir.mkdirs()) {
                throw new Exception("Cannot create directory: " + parentDir.getAbsolutePath());
            }
        }

        logInfo("Downloading from " + downloadUrl + " → " + destFile.getAbsolutePath());

        // Retry loop
        Exception lastError = null;
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                long bytesDownloaded = performDownload(downloadUrl, destFile,
                        new ProgressCallback() {
                            @Override
                            public void onProgress(long bytesTransferred, long totalBytes) {
                                if (totalBytes > 0) {
                                    int pct = (int) (bytesTransferred * 100 / totalBytes);
                                    logDebug("Download progress: " + pct + "%");
                                }
                            }
                        });

                JSONObject result = new JSONObject();
                result.put("dest", destFile.getAbsolutePath());
                result.put("size_bytes", bytesDownloaded);
                logInfo("Download successful: " + bytesDownloaded + " bytes");
                return result.toString();

            } catch (java.net.SocketTimeoutException e) {
                lastError = e;
                Log.w(TAG, "Download attempt " + attempt + " timed out, retrying...");
                // Delete partial file before retry
                if (destFile.exists()) destFile.delete();
                Thread.sleep(1000L * attempt);
            }
        }
        throw new Exception("Download failed after " + MAX_RETRIES + " attempts: "
                + lastError.getMessage());
    }

    /**
     * performDownload() - actual HTTP GET download
     */
    private long performDownload(String downloadUrl, File destFile,
                                  ProgressCallback progressCallback) throws Exception {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(downloadUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);

            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new Exception("Server returned HTTP " + responseCode);
            }

            long contentLength = conn.getContentLengthLong();

            InputStream in = conn.getInputStream();
            FileOutputStream fos = new FileOutputStream(destFile);
            byte[] buffer = new byte[BUFFER_SIZE];
            long totalReceived = 0;
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
                totalReceived += bytesRead;
                if (progressCallback != null) {
                    progressCallback.onProgress(totalReceived, contentLength);
                }
            }
            fos.flush();
            fos.close();
            in.close();

            return totalReceived;

        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Security Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * validateFilePath() - path traversal attacks prevent करें
     * केवल /sdcard/ और /data/user/ paths allowed हैं
     */
    private void validateFilePath(File file) throws SecurityException {
        String canonicalPath = file.getAbsolutePath();

        // Allowed base paths (adjust as needed for your app)
        boolean allowed = canonicalPath.startsWith("/sdcard/")
                || canonicalPath.startsWith("/storage/emulated/")
                || canonicalPath.startsWith("/data/user/");

        if (!allowed) {
            throw new SecurityException(
                    "File path not allowed (path traversal prevention): " + canonicalPath);
        }
    }

    /**
     * detectMimeType() - file extension से MIME type detect करें
     */
    private String detectMimeType(String filePath) {
        String lower = filePath.toLowerCase();
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".png"))  return "image/png";
        if (lower.endsWith(".gif"))  return "image/gif";
        if (lower.endsWith(".mp4"))  return "video/mp4";
        if (lower.endsWith(".mp3"))  return "audio/mpeg";
        if (lower.endsWith(".pdf"))  return "application/pdf";
        if (lower.endsWith(".txt"))  return "text/plain";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".zip"))  return "application/zip";
        return "application/octet-stream";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Progress Callback Interface
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * ProgressCallback - file transfer progress notifications
     */
    public interface ProgressCallback {
        /**
         * @param bytesTransferred  Bytes transferred so far
         * @param totalBytes        Total bytes (-1 if unknown)
         */
        void onProgress(long bytesTransferred, long totalBytes);
    }
}
