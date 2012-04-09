/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package burp;

import burp.interfaces.IHttpRequestResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;

/**
 *
 * Custom implementation of IHttpRequestResponse
 *
 * @author Daniel Garcia Garcia (cr0hn) - dani@iniqua.comel Garcia Garcia aka cr0hn
 */
public class CustomHttpRequestResponse implements IHttpRequestResponse {

    private URL _url;
    private byte[] _request = null;
    private byte[] _response = null;
    private short _status = 200;
    private String _host = null;
    private String _path = null;
    private int _port = -1;
    private String _protocol = null;
    private String _comment = null;
    private String _cookie = null;
    private String _post_data = null;
    private String _method = "GET";
    private String _srequest = null;

    public CustomHttpRequestResponse(String url) throws MalformedURLException, IOException
    {       
        // Extract URL info
        this._splitURL(url);

        this._connect();
    }

    public CustomHttpRequestResponse(String url, String cookie, String postData, String Method) throws MalformedURLException, IOException
    {
        this._cookie = cookie;
        this._post_data = postData;
        this._method = (Method==null||Method.isEmpty()?"GET":Method);

        // Extract URL info
        this._splitURL(url);

        this._connect();
    }

    /***
     * Extract URL info like: host, port, protocol and file.
     * @param url URL to extract
     * @throws MalformedURLException
     */
    private void _splitURL(String url) throws MalformedURLException
    {

        /*
         * Split URL info.
         *
         * Format: PROTOCOL://URI/FILE
         */
        _url = new URL(url);
        // Protocol
        this._protocol = (_url.getProtocol().isEmpty()?"http":_url.getProtocol());
        // Path
        this._path = (_url.getPath().isEmpty()?"/":_url.getPath());
        // URI
        this._host = _url.getHost();
        // Port
        this._port = (_url.getPort()==-1?80:_url.getPort());
    }


    @Override
    public String getHost() {
        return this._host;
    }

    @Override
    public int getPort() {
        return this._port;
    }

    @Override
    public String getProtocol() {
        return this._protocol;
    }


    @Override
    public byte[] getRequest() throws Exception {
        return this._request;
    }

    @Override
    public URL getUrl() throws Exception {
        return this._url;
    }

    @Override
    public byte[] getResponse() throws Exception {
        return this._response;
    }

    @Override
    public short getStatusCode() throws Exception {
        return this._status;
    }

    @Override
    public String getComment() throws Exception {
        return this._comment;
    }

    /**
     * Make a connection to host
     * @throws IOException
     */
    private void _connect() throws IOException
    {
        Socket socket = null;
        PrintWriter writer = null;
        BufferedReader reader = null;

        // Make request
        this._makeRequest();

        try {
            socket = new Socket(_host, _port);
            writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            writer.write(_srequest);
            writer.flush();

            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            StringBuilder m_sresponse = new StringBuilder(4000);
            for (String line; (line = reader.readLine()) != null;) {
                if (line.isEmpty()) break; // Stop when headers are completed. We're not interested in all the HTML.

                // Append to response
                m_sresponse.append(line);
            }
            

            // Get bytes, to implement the interface.
            this._response = m_sresponse.toString().getBytes();

        } finally {
            if (reader != null) try { reader.close(); } catch (IOException logOrIgnore) {}
            if (writer != null) { writer.close(); }
            if (socket != null) try { socket.close(); } catch (IOException logOrIgnore) {}
        }
    }


    /**
     * Make a HTTP request
     */
    private void _makeRequest() throws MalformedURLException, IOException
    {
        StringBuilder m_request = new StringBuilder(600);

        /*
         * Make Request connection
         */
        // GET/POST
        m_request.append(_method);
        m_request.append(" ");
        m_request.append(_path);
        m_request.append(" ");
        m_request.append("HTTP/1.1");
        m_request.append("\r\n");

        // Host
        m_request.append("Host: ");
        m_request.append(_host);
        m_request.append(":");
        m_request.append(_port);
        m_request.append("\r\n");

        // Cookie?
        if(_cookie != null && !_cookie.isEmpty())
        {
            m_request.append("Cookie: ");
            m_request.append(_cookie);
            m_request.append("\r\n");
        }
        // Post data?
        if(_post_data != null && !_cookie.isEmpty())
        {
            // Calculate length
            int m_length = _post_data.length();
            // Add Content-Length: Header
            m_request.append("Content-Length: ");
            m_request.append(m_length);
            m_request.append("\r\n");

            // Add post data
            m_request.append("\r\n\r\n");
            m_request.append(_post_data);
        }

        m_request.append("\r\n\r\n");

        this._srequest = m_request.toString();

        // Get bytes for implement interface
        this._request = m_request.toString().getBytes();
    }






    /******************************************************
     *
     *
     * Setters: Not implemented because are not necessary.
     * 
     * 
     ******************************************************/
    @Override
    public void setComment(String comment) throws Exception {

    }
        @Override
    public void setRequest(byte[] message) throws Exception {

    }

    @Override
    public void setHost(String host) throws Exception {

    }

    @Override
    public void setPort(int port) throws Exception {

    }

    @Override
    public void setProtocol(String protocol) throws Exception {

    }

    @Override
    public void setResponse(byte[] message) throws Exception {

    }
}