/* Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wslite.http

import wslite.http.auth.*

import java.util.zip.GZIPInputStream

class HTTPClient {

    int connectTimeout = 0
    int readTimeout = 0
    boolean followRedirects = true
    boolean useCaches
    boolean sslTrustAllCerts
    String sslTrustStoreFile
    String sslTrustStorePassword

    Proxy proxy

    def defaultHeaders = [Connection:'Close', 'Accept-Encoding':'gzip']

    HTTPConnectionFactory httpConnectionFactory
    HTTPAuthorization authorization

    HTTPClient() {
        httpConnectionFactory = new HTTPConnectionFactory()
    }

    HTTPClient(HTTPConnectionFactory httpConnectionFactory) {
         this.httpConnectionFactory = httpConnectionFactory
    }

    HTTPResponse execute(HTTPRequest request) {
        if (!(request?.url && request?.method)) {
            throw new IllegalArgumentException('HTTP Request must contain a url and method')
        }
        HTTPResponse response
        def conn
        try {
            conn = createConnection(request)
            setupConnection(conn, request)
            response = buildResponse(conn, conn.inputStream)
        } catch(Exception ex) {
            if (!conn) {
                throw new HTTPClientException(ex.message, ex, request, response)
            } else {
                response = buildResponse(conn, conn.errorStream)
                throw new HTTPClientException(response.statusCode + ' ' + response.statusMessage,
                        ex, request, response)
            }
        } finally {
            conn?.disconnect()
        }
        return response
    }

    private createConnection(HTTPRequest request) {
        if (isSecureConnectionRequest(request)) {
            def usedProxy = getProxy(request, true)
            if (shouldTrustAllSSLCerts(request)) {
                return httpConnectionFactory.getConnectionTrustAllSSLCerts(request.url, usedProxy)
            }
            if (shouldTrustSSLCertsUsingTrustStore(request)) {
                String trustStoreFile
                String trustStorePassword
                if (request.sslTrustStoreFile) {
                    trustStoreFile = request.sslTrustStoreFile
                    trustStorePassword = request.sslTrustStorePassword
                } else {
                    trustStoreFile = sslTrustStoreFile
                    trustStorePassword = sslTrustStorePassword
                }
                return httpConnectionFactory.getConnectionUsingTrustStore(request.url,
                        trustStoreFile, trustStorePassword, usedProxy)
            }
        }
        return httpConnectionFactory.getConnection(request.url, getProxy(request, false))
    }

    private boolean isSecureConnectionRequest(HTTPRequest request) {
        return request.url.protocol.toLowerCase() == 'https'
    }

    private boolean shouldTrustAllSSLCerts(HTTPRequest request) {
        return request.isSSLTrustAllCertsSet ? request.sslTrustAllCerts : sslTrustAllCerts
    }

    private boolean shouldTrustSSLCertsUsingTrustStore(HTTPRequest request) {
        return request.sslTrustStoreFile !=null || sslTrustStoreFile !=null
    }

    private void setupConnection(conn, HTTPRequest request) {
        conn.setRequestMethod(request.method.toString())
        conn.setConnectTimeout(request.isConnectTimeoutSet ? request.connectTimeout : connectTimeout)
        conn.setReadTimeout(request.isReadTimeoutSet ? request.readTimeout : readTimeout)
        conn.setUseCaches(request.isUseCachesSet ? request.useCaches : useCaches)
        conn.setInstanceFollowRedirects(request.isFollowRedirectsSet ? request.followRedirects : followRedirects)
        setRequestHeaders(conn, request)
        setAuthorizationHeader(conn)
        if (request.data) {
            conn.setDoOutput(true)
            if (conn.getRequestProperty(HTTP.CONTENT_LENGTH_HEADER) == null) {
                conn.setRequestProperty(HTTP.CONTENT_LENGTH_HEADER, "${request.data.size()}")
            }
            conn.outputStream.bytes = request.data
        }
    }

    private void setRequestHeaders(conn, request) {
        for (entry in request.headers) {
            setConnectionRequestProperty(conn, entry.key, entry.value)
        }
        for (entry in defaultHeaders) {
            if (conn.getRequestProperty(entry.key) == null) {
                setConnectionRequestProperty(conn, entry.key, entry.value)
            }
        }
    }

    private void setConnectionRequestProperty(conn, String key, List values) {
        for (val in values) {
            setConnectionRequestProperty(conn, key, val.toString())
        }
    }

    private void setConnectionRequestProperty(conn, String key, String value) {
        conn.setRequestProperty(key, value)
    }

    private void setAuthorizationHeader(conn) {
        if (authorization) {
            authorization.authorize(conn)
        }
    }

    private HTTPResponse buildResponse(conn, responseStream) {
        def response = new HTTPResponse()
        
        println("building response")

        response.statusCode = conn.responseCode
        response.statusMessage = conn.responseMessage
        response.url = conn.URL
        response.contentEncoding = conn.contentEncoding
        response.contentLength = conn.contentLength
        
        ContentTypeHeader contentTypeHeader = new ContentTypeHeader(conn.contentType)
        response.contentType = contentTypeHeader.mediaType
        response.charset = contentTypeHeader.charset
        response.contentTypeHeader = contentTypeHeader

        response.date = new Date(conn.date)
        response.expiration = new Date(conn.expiration)
        response.lastModified = new Date(conn.lastModified)
        response.headers = headersToMap(conn)

        if(contentTypeHeader.isMtom){
            println("ContentType Header is mtom")
            try {
                parseMtomMessage(response, conn.getInputStream())
            } catch (Exception e){
                println("unable to parse mtom message")
                e.printStackTrace()
            }
            
            //only store the soap text in the data byte[]
            //refine later
            //response.data = getResponseContent(responseStream, conn.contentEncoding)
        } else {
            println("ContentType Header is not mtom")
            response.data = getResponseContent(responseStream, conn.contentEncoding)
        }

        return response
    }

    private getResponseContent(inputStream, contentEncoding) {
        if (!inputStream) {
            return null
        }
        return (contentEncoding == 'gzip') ? new GZIPInputStream(inputStream)?.bytes : inputStream.bytes
    }

    private Map headersToMap(conn) {
        def headers = [:]
        for (entry in conn.headerFields) {
            headers[entry.key ?: ''] = entry.value.size() > 1 ? entry.value : entry.value[0]
        }
        return headers
    }

    private void parseMtomMessage(httpResponse, responseStream){

        def contentTypeHeader = httpResponse.contentTypeHeader
        
        String boundary = contentTypeHeader.boundary
        //add the dashes so they don't get parsed into the message
        //TODO: make a configuration option 
        boundary = "--"+boundary

        println("parsing mtom message with boundary "+boundary)

        byte[] bbytes = boundary.bytes

        int numIndiciesHeld = 0;

        //window that will scan through the stream. Used to check for mime boundaries
        byte[] boundaryChecker = new byte[bbytes.length]
        long totalBoundaryUpdateTime = 0

        //save the previous byte
        byte lastByte = (byte)0;

        //list of each of the mtom message parts
        def messageParts = []

        //structure holding 1 message part. Will have a type, the headers, and content. Content may be a file name or byte array.
        def messagePart = ["headers":[], "type":"unkown", "content":[]]
        //list of headers per message part
        def headers = []
        //container for the bytes
        def content = []

        //place to keep the bytes found for a header
        def tempMessagePartHeader = []
        //temp file we need to store attachments
        File tempAttachment = null;
        //FileOutputStream to write bytes to temp file
        def fos = null
        //buffer for writing to disc more efficiently
        def buffer = new byte[4096]
        int numBytesInBuffer = 0
        long totalWriteTime = 0

        boolean inMessagePart = false;
        int numMessagePartsFound = 0;
        int numLineFeedsFound = 0
        boolean isMessageContent = false;
        boolean boundaryFoundThisByte = false

        long startTime = System.currentTimeMillis()

        responseStream.eachByte{ b -> 
            //update the boundary checker with the new byte (forcing the byte on the left of the buffer out if length if met)
            long updateBoundaryCheckerTimeStart = System.currentTimeMillis()
            numIndiciesHeld = updateBoundaryChecker(boundaryChecker, numIndiciesHeld, b)
            totalBoundaryUpdateTime += System.currentTimeMillis() - updateBoundaryCheckerTimeStart
            
            //test if the buffer equals the bytes of the boundary (we've found a boundary)
            if(Arrays.equals(boundaryChecker, bbytes)){
                println("found boundary")
                inMessagePart = true
                boundaryFoundThisByte = true
                numMessagePartsFound++
                if(numMessagePartsFound > 1){
                    //clean up content
                    if(messagePart["type"] == "soap"){
                        println("content was soap")
                        //content was the soap message and should be a byte array containing the message
                        //copy the message truncating the written mime boundary (could be heavy on memory for large soap responses)
                        byte[] contentBytes = messagePart["content"] as byte[]
                        //println(messagePart["content"])
                        //println(contentBytes.length)
                        messagePart["content"] = new String(Arrays.copyOf(contentBytes, contentBytes.length - bbytes.length+1))
                    } else {
                        println("content was attachment")
                        //content was an attachment
                        //check if there are bytes left to write
                        if(numBytesInBuffer > 0){
                            //write out the bytes
                            if(fos != null){
                                long startWriteTime = System.currentTimeMillis()
                                fos.write(buffer, 0, numBytesInBuffer)
                                totalWriteTime += System.currentTimeMillis() - startWriteTime
                                println("wrote entrie attachment in ${totalWriteTime}")
                                numBytesInBuffer = 0
                            } else {
                                println("unempty buffer buf file was already closed!!")
                            }
                        }
                        //first close the steam to the file
                        if(fos != null){
                            try{
                                fos.close()
                            } catch (Exception closeEx){
                                println("Unable to close output stream to file for attachment")
                                closeEx.printStackTrace()
                            }
                        }
                        try{
                            long rafTimer = System.currentTimeMillis()
                            //use tempAttachment File reference to truncate the end of the file
                            RandomAccessFile raf = new RandomAccessFile(tempAttachment, "rw")
                            //remove the mimeboundary plus the line feed from the end of the file
                            raf.setLength(raf.length() - bbytes.length+1)
                            println("truncated filed in ${System.currentTimeMillis() - rafTimer}")
                            //release resources
                            raf.close()
                            tempAttachment = null

                        } catch (Exception rafEx){
                            println("Exception while truncating attachment")
                            rafEx.printStackTrace()
                        }
                    }
                    //add this message part to the list of message parts
                    messageParts << messagePart
                    //initialize messagePart
                    messagePart = ["headers":[], "type":"unkown", "content":[]]
                    //reset variables for further processing
                    numLineFeedsFound = 0
                    isMessageContent = false
                }
            } else {
                boundaryFoundThisByte = false
            }
            if(inMessagePart && !boundaryFoundThisByte){
                if(!isMessageContent){
                    //we are dealing with headers
                    if(b != (byte)10 && b != (byte)13){
                        //this is assuming that a header will not have a line feed in it and that headers are broken up by line feeds
                        tempMessagePartHeader << b
                        //println("setting line feed to 0")
                        numLineFeedsFound = 0
                    } else {
                        if(b != (byte)13){
                            numLineFeedsFound++
                        }
                        //println("found line feed. ${numLineFeedsFound}")
                        if(numLineFeedsFound == 1 && tempMessagePartHeader.size() > 0){
                            def header = new String(tempMessagePartHeader as byte[])
                            messagePart["headers"] << header
                            //check each header when it's added to see if it is the soap response
                            if(header.contains("application/xop+xml")){
                                messagePart["type"] = "soap"
                                println("found header : ${header}\nsetting message part type to soap")
                            }
                            //clear the tempHeader for the next one
                            tempMessagePartHeader = []
                        }
                    }
                    if(numLineFeedsFound == 2){
                        //next byte will be part of messagePart content. Do nothing with this byte
                        isMessageContent = true
                    }
                } else {
                    if(messagePart["type"] == "soap"){
                        //soap message written directly to content of messagePart (memory)
                        messagePart["content"] << b
                        //println(messagePart["content"])
                    } else {
                        if(messagePart["type"] == "unknown"){
                            messagePart["type"] == "attachment"
                        }
                        //this is an attachment. Write it out to disk using tempFile
                        //write to disk
                        //if(tempAttachment == null || !tempAttachment.existempAttachmentts()){
                        if(tempAttachment == null){
                            try{
                                tempAttachment = File.createTempFile("message", ".dat");
                                messagePart["content"] = tempAttachment.getAbsolutePath()
                                fos = new FileOutputStream(tempAttachment);
                                println("writing attachment to ${tempAttachment.getAbsolutePath()}")
                            } catch(Exception e){
                                println("unable to write attachment to disk")
                                e.printStackTrace()
                            }
                        }
                        if(fos != null){
                            if(numBytesInBuffer < buffer.length){
                                buffer[numBytesInBuffer] = b
                                numBytesInBuffer++
                            } else {
                                long startWriteTime = System.currentTimeMillis()
                                fos.write(buffer, 0, numBytesInBuffer)
                                //Thread.sleep(1000)
                                long writeTime = System.currentTimeMillis() - startWriteTime
                                totalWriteTime += writeTime
                                println("wrote ${numBytesInBuffer} in ${writeTime}")
                                numBytesInBuffer = 0
                                buffer[numBytesInBuffer] = b
                                numBytesInBuffer++
                            }
                        }
                    }
                }
            }
        }
        println("total boundary update time ${totalBoundaryUpdateTime}")
        println("time it took to parse mtom message ${System.currentTimeMillis() - startTime}")
        
        println(messageParts)

        messageParts.each {mp ->
            if(mp["type"] == "soap"){
                httpResponse.data = mp["content"] as byte[]
                println("set response data as byte[]")
            }
        }
    }

    private int updateBoundaryChecker(boundaryChecker, numIndiciesHeld, byte newB){
        if(numIndiciesHeld < boundaryChecker.length){
            boundaryChecker[numIndiciesHeld] = newB
            numIndiciesHeld++
            return numIndiciesHeld
        } else {
            //shift every byte down one index (get rid of the furthest left)
            for(int i = 0; i < boundaryChecker.length; i++){
                if(i+1 < boundaryChecker.length){
                    boundaryChecker[i] = boundaryChecker[i+1]
                } else {
                    boundaryChecker[i] = newB
                }
            }
            return numIndiciesHeld
        }
    }

    /**
     * Returns the proxy to use for the given request. The first proxy in the
     * following list that is defined gets selected:
     * <ol>
     * <li>request.proxy</li>
     * <li>HTTPClient's {@code proxy} property</li>
     * <li>{@code http(s).proxyHost/Port} system properties</li>
     * <li>no proxy</li>
     * </ol>
     * @param request The current HTTP(S) request.
     * @param useHttpsProxy If {@code true}, the HTTPS proxy is returned, otherwise
     * the method returns the standard HTTP one.
     */
    private Proxy getProxy(request, useHttpsProxy) {
        return request.proxy ?: proxy ?: loadSystemProxy(useHttpsProxy) ?: Proxy.NO_PROXY
    }

    /**
     * Reads the proxy information from the {@code http(s).proxyHost} and {@code http(s).proxyPort}
     * system properties if set and returns a {@code java.net.Proxy} instance configured with
     * those settings. If the {@code proxyHost} setting has no value, then this method returns
     * {@code null}.
     * @param useHttpsProxy {@code true} if you want the HTTPS proxy, otherwise {@code false}.
     */
    private Proxy loadSystemProxy(boolean useHttpsProxy) {
        def propertyPrefix = useHttpsProxy ? "https" : "http"
        def proxyHost = System.getProperty("${propertyPrefix}.proxyHost")
        if (!proxyHost) return null

        def proxyPort = System.getProperty("${propertyPrefix}.proxyPort")?.toInteger()
        proxyPort = proxyPort ?: (useHttpsProxy ? 443 : 80)

        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort))
    }

}
