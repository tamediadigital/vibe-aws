/**
  Vibe-based AWS client
 */

module vibe.aws.aws;

import std.algorithm;
import std.datetime;
import std.random;
import std.range;
import std.stdio;
import std.string;
import std.conv;

import vibe.core.stream;
import vibe.core.core;
import vibe.core.log;
import vibe.data.json;
import vibe.http.client;
import vibe.inet.message;
import vibe.http.common;

import std.digest.sha;
import vibe.aws.sigv4;
import std.math;

import memutils.all;
import arsd.dom;

public import vibe.aws.credentials;

class AWSException : Exception
{
    immutable string type;
    immutable bool retriable;

    this(string type, bool retriable, string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        super(type ~ ": " ~ message, file, line, next);
        this.type = type;
        this.retriable = retriable;
    }

    /**
      Returns the 'ThrottlingException' from 'com.amazon.coral.service#ThrottlingException'
     */
    @property string simpleType() 
    {
        auto h = type.indexOf('#');
        if (h == -1) return type;
        return type[h+1..$];
    }
}

/**
  Configuraton for AWS clients
 */
struct ClientConfiguration
{
    uint maxErrorRetry = 3;
}

/**
  Thrown when the signature/authorization information is wrong
 */
class AuthorizationException : AWSException
{
    this(string type, string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        super(type, false, message, file, line, next);
    }
}

struct ExponentialBackoff
{
    immutable uint maxRetries;
    uint tries = 0;
    uint maxSleepMs = 10;

    this(uint maxRetries)
    {
        this.maxRetries = maxRetries;
    }

    @property bool canRetry()
    {
        return tries < maxRetries;
    }

    @property bool finished()
    {
        return tries >= maxRetries + 1;
    }

    void inc()
    {
        tries++;
        maxSleepMs *= 2;
    }

    void sleep()
    {
        vibe.core.core.sleep(uniform!("[]")(1, maxSleepMs).msecs);
    }

    int opApply(scope int delegate(uint) attempt)
    {
        int result = 0;
        for (; !finished; inc())
        {
            try
            {
                result = attempt(maxRetries - tries);
                if (result)
                    return result;
            }
            catch (AWSException e)
            {
                logWarn(typeid(e).name ~ " occurred at " ~ e.file ~ ":" ~ e.line.to!string ~ " : " ~ e.msg);
                // Retry if possible and retriable, otherwise give up.
                if (!canRetry || !e.retriable) 
                    throw e;
            }
            catch (Exception e) //ssl errors from ssl.d
            {
                logWarn(typeid(e).name ~ " occurred at " ~ e.file ~ ":" ~ e.line.to!string ~ " : " ~ e.msg);
                if (!canRetry)
                    throw e;
            }
            sleep();
        }
        return result;
    }
}

abstract class RESTClient {
    immutable string endpoint;
    immutable string region;
    immutable string service;

    private AWSCredentialSource m_credsSource;
    private ClientConfiguration m_config;

    this(string endpoint, string region, string service, AWSCredentialSource credsSource, ClientConfiguration config=ClientConfiguration()) 
    {
        this.region = region;
        this.endpoint = endpoint;
        this.service = service;
        this.m_credsSource = credsSource;
        this.m_config = config;
    }

    private static string buildQueryParameterString(string[string] queryParameters)
    {
        import vibe.textfilter.urlencode;

        auto stringBuilder = appender!string;
        bool firstParameter = true;
        foreach(parameter, value; queryParameters)
        {
            if (firstParameter)
                firstParameter = false;
            else
                stringBuilder.put("&");

            stringBuilder.put(urlEncode(parameter));
            if(value)
            {
                stringBuilder.put("=");
                stringBuilder.put(urlEncode(value));
            }
        }
        return stringBuilder.data;
    }

    HTTPClientResponse doRequest(HTTPMethod method, string resource, string[string] queryParameters, in InetHeaderMap headers, in ubyte[] reqBody = null)
    {
        if (!resource.startsWith("/"))
            resource = "/" ~ resource;

        //Initialize credentials
        auto credScope = region ~ "/" ~ service;
        auto creds = m_credsSource.credentials(credScope);

        auto queryString = buildQueryParameterString(queryParameters);

        auto retries = ExponentialBackoff(m_config.maxErrorRetry);
        foreach(triesLeft; retries)
        {
            HTTPClientResponse resp;
            scope(failure) 
                if (resp)
                {
                    resp.dropBody();
                    resp.destroy();
                }
            auto url = "https://" ~ endpoint ~ resource ~ "?" ~ queryString;
            resp = requestHTTP(url, (scope HTTPClientRequest req) {
                req.method = method;
                
                foreach(key, value; headers)
                    req.headers[key] = value;

                req.headers["host"] = endpoint;
                auto timeString = currentTimeString();
                req.headers["x-amz-date"] = timeString;
                req.headers["x-amz-content-sha256"] = sha256Of(reqBody).toHexString().toLower();
                if (creds.sessionToken && !creds.sessionToken.empty)
                    req.headers["x-amz-security-token"] = creds.sessionToken;
                signRequest(req, queryParameters, reqBody, creds, timeString, region, service);
                if (reqBody)
                    req.writeBody(reqBody);
            });
            checkForError(resp);
            return resp;
        }
        assert(0);
    }

    HTTPClientResponse doUpload(HTTPMethod method, string resource, string[string] queryParameters,
                                in InetHeaderMap headers, in string[] additionalSignedHeaders,
                                scope RandomAccessStream payload, ulong blockSize = 512*1024)
    {
        auto retries = ExponentialBackoff(m_config.maxErrorRetry);
        foreach(triesLeft; retries)
        {
            payload.seek(0);
            return doUpload(method, resource, queryParameters, headers, additionalSignedHeaders,
                            payload, payload.size, blockSize);
        }
        assert(0);
    }

    HTTPClientResponse doUpload(HTTPMethod method, string resource, string[string] queryParameters,
                                in InetHeaderMap headers, in string[] additionalSignedHeaders,
                                scope InputStream payload, ulong payloadSize, ulong blockSize = 512*1024)
    {
        //Calculate the body size upfront for the "Content-Length" header
        logDebug("doUpload for resource %s", resource);
        auto base16 = (ulong x) => ceil(log2(x)/4).to!ulong;
        enum ulong signatureSize = ";chunk-signature=".length + 64;
        immutable ulong numFullSizeBlocks = payloadSize / blockSize;
        immutable ulong lastBlockSize = payloadSize % blockSize;
        
        immutable ulong bodySize =  numFullSizeBlocks * (base16(blockSize)  + signatureSize + 4 + blockSize) //Full-Sized blocks (4 = 2*"\r\n")
                                 + (lastBlockSize  ? (base16(lastBlockSize) + signatureSize + 4 + lastBlockSize) : 0) //Part-Sized last block
                                 + (1 + signatureSize + 4); //Finishing 0-sized block


        if (!resource.startsWith("/"))
            resource = "/" ~ resource;

        //Initialize credentials
        auto credScope = region ~ "/" ~ service;
        auto creds = m_credsSource.credentials(credScope);

        HTTPClientResponse resp;
        scope(failure) 
            if (resp)
            {
                resp.dropBody();
                resp.destroy();
            }

        auto url = "https://" ~ endpoint ~ resource;
        if (queryParameters !is null)
        {
            url ~= "?" ~ buildQueryParameterString(queryParameters);
        }

        resp = requestHTTP(url, (scope HTTPClientRequest req) {
            req.method = method;
            
            //Initialize the headers
            foreach(key, value; headers)
                req.headers[key] = value;

            //Since we might be doing retries, update the date
            auto isoTimeString = currentTimeString();
            req.headers["x-amz-date"] = isoTimeString;
            auto date = isoTimeString.dateFromISOString;
            auto time = isoTimeString.timeFromISOString;
            
            //Adjust the headers necessary for a chunked transmission
            string newEncoding = "aws-chunked";
            if ("Content-Encoding" in headers)
                newEncoding ~= "," ~headers["Content-Encoding"];
            
            if ("Content-Type" in headers)
                req.contentType = headers["Content-Type"];
            else
                req.contentType = "application/octet-stream";
            
            req.headers["Content-Length"] = bodySize.to!string;
            req.headers["Content-Encoding"] = newEncoding;
            req.headers["x-amz-content-sha256"] = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
            req.headers["x-amz-decoded-content-length"] = payloadSize.to!string;

            //Seems not to be working properly (S3 returns error if "Content-Length" is not used)
//                req.headers["Transfer-Encoding"] = "chunked";
//                if ("Content-Length" in headers)
//                    req.headers.remove("Content-Length");

            auto canonicalRequest = CanonicalRequest(
                    method.to!string,
                    resource,
                    queryParameters,
                    [
                        "host":                         req.headers["host"],
                        "content-encoding":             req.headers["Content-Encoding"],
                        "content-length":               req.headers["Content-Length"],
                        "x-amz-content-sha256":         req.headers["x-amz-content-sha256"],
                        "x-amz-date":                   req.headers["x-amz-date"],
                        "x-amz-decoded-content-length": req.headers["x-amz-decoded-content-length"],
//                        "transfer-encoding":            req.headers["Transfer-Encoding"],
                    ],
                    null
                );

            foreach (key; additionalSignedHeaders)
                canonicalRequest.headers[key] = req.headers[key];

            //Calculate the seed signature
            auto signableRequest = SignableRequest(date, time, region, service, canonicalRequest);
            auto key = signingKey(creds.accessKeySecret, date, region, service);
            auto binarySignature = key.sign(cast(ubyte[])signableRequest.signableStringForStream);

            auto credScope = date ~ "/" ~ region ~ "/" ~ service;
            auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, canonicalRequest.headers, binarySignature);
            req.headers["authorization"] = authHeader;

            //Write the data in chunks to the stream
            auto outputStream = createChunkedOutputStream(req.bodyWriter);
            outputStream.maxBufferSize = blockSize;
//            auto outputStream = cast(ChunkedOutputStream) req.bodyWriter;
//            enforce(outputStream !is null);

            string signature = binarySignature.toHexString().toLower();
            outputStream.chunkExtensionCallback = (in ubyte[] data) @safe
            {
                logDebug("doUpload: chunkExtensionCallback data is %s bytes", data.length);
                auto chunk = SignableChunk(date, time, region, service, signature, hash(data));
                signature = key.sign(chunk.signableString.representation).toHexString().toLower();
                return "chunk-signature=" ~ signature;
            };
            logDebug("doUpload: write payload");
            payload.pipe(outputStream);
            logDebug("doUpload: finalize ... ");
            outputStream.finalize;
            logDebug("doUpload: finalized.");
        });
        checkForError(resp);
        return resp;
    }

    Document readXML(HTTPClientResponse response)
    {
        auto stringBuilder = appender!string;
        auto reader = response.bodyReader;

        auto buffer = ThreadMem.alloc!(ubyte[])(1024);
        scope(exit)
            ThreadMem.free(buffer);

        while(reader.leastSize > 0)
        {
            auto size = min(reader.leastSize,buffer.length);
            auto bytes = buffer[0..size];
            reader.read(bytes);
            stringBuilder.put(bytes);
        }
        return new Document(stringBuilder.data);
    }

    void checkForError(HTTPClientResponse response, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        if (response.statusCode < 400) 
            return; // No error

        auto document = readXML(response);
        auto code = document.querySelector("Error Code").innerText;
        auto message = document.querySelector("Error Message").innerText;
        logError(message);
        throw makeException(code, response.statusCode / 100 == 5, message, file, line, next);
    }

    AWSException makeException(string type, bool retriable, string message,
        string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        if (type == "UnrecognizedClientException" 
         || type == "InvalidSignatureException")
            throw new AuthorizationException(type, message, file, line, next);
        return new AWSException(type, retriable, message, file, line, next);
    }
}

class AWSClient {
    protected static immutable exceptionPrefix = "com.amazon.coral.service#";

    immutable string endpoint;
    immutable string region;
    immutable string service;

    private AWSCredentialSource m_credsSource;
    private ClientConfiguration m_config;

    this(string endpoint, string region, string service, AWSCredentialSource credsSource, ClientConfiguration config=ClientConfiguration()) 
    {
        this.region = region;
        this.endpoint = endpoint;
        this.service = service;
        this.m_credsSource = credsSource;
        this.m_config = config;
    }

    AWSResponse doRequest(string operation, Json request)
    {
        auto backoff = ExponentialBackoff(m_config.maxErrorRetry);

        for (; !backoff.finished; backoff.inc())
        {
            auto credScope = region ~ "/" ~ service;
            auto creds = m_credsSource.credentials(credScope);
            HTTPClientResponse resp;
            try
            {
                // FIXME: Auto-retries for retriable errors
                // FIXME: Report credential errors and retry for failed credentials
                 resp = requestHTTP("https://" ~ endpoint ~ "/", (scope req) {
                    auto timeString = currentTimeString();
                    auto jsonString = cast(ubyte[])request.toString();

                    req.method = HTTPMethod.POST;
                    req.headers["x-amz-target"] = operation;
                    req.headers["x-amz-date"] = currentTimeString();
                    req.headers["host"] = endpoint;
                    if (creds.sessionToken && !creds.sessionToken.empty)
                        req.headers["x-amz-security-token"] = creds.sessionToken;
                    req.contentType = "application/x-amz-json-1.1";
                    signRequest(req, null, jsonString, creds, timeString, region, service);
                    req.writeBody(jsonString);
                });

                checkForError(resp);

                return new AWSResponse(resp);
            }
            catch (AuthorizationException ex)
            {
                logWarn(ex.msg);
                // Report credentials as invalid. Will retry if possible.
                m_credsSource.credentialsInvalid(credScope, creds, ex.msg);
                resp.dropBody();
                resp.destroy();
                if (!backoff.canRetry) throw ex;
            }
            catch (AWSException ex)
            {
                logWarn(ex.msg);
                resp.dropBody();
                resp.destroy();
                // Retry if possible and retriable, otherwise give up.
                if (!backoff.canRetry || !ex.retriable) throw ex;
            } 
            catch (Throwable t) //ssl errors from ssl.d
            {
              if (!backoff.canRetry)
              {
                vibe.core.log.logError("no retries left, failing request");
                throw(t);
              }
            }
            backoff.sleep();
        }
        assert(0);
    }

    void checkForError(HTTPClientResponse response)
    {
        if (response.statusCode < 400) return; // No error

        auto bod = response.readJson();

        throw makeException(bod["__type"].get!string, response.statusCode / 100 == 5, bod["message"].opt!string(""));
    }

    AWSException makeException(string type, bool retriable, string message)
    {
        if (type == exceptionPrefix ~ "UnrecognizedClientException" || type == exceptionPrefix ~ "InvalidSignatureException")
            throw new AuthorizationException(type, message);
        return new AWSException(type, retriable, message);
    }
}

private auto currentTimeString()
{
    auto t = Clock.currTime(UTC());
    t.fracSecs = 0.seconds;
    return t.toISOString();
}

private void signRequest(HTTPClientRequest req, string[string] queryParameters,
                         in ubyte[] requestBody, AWSCredentials creds, 
                         string timeString, string region, string service)
{
    auto dateString = dateFromISOString(timeString);
    auto credScope = dateString ~ "/" ~ region ~ "/" ~ service;

    SignableRequest signRequest;
    signRequest.dateString = dateString;
    signRequest.timeStringUTC = timeFromISOString(timeString);
    signRequest.region = region;
    signRequest.service = service;
    signRequest.canonicalRequest.method = req.method.to!string();

    auto pos = req.requestURL.indexOf("?");
    if (pos < 0)
        pos = req.requestURL.length;
    signRequest.canonicalRequest.uri = req.requestURL[0..pos];

    signRequest.canonicalRequest.queryParameters = queryParameters;

    auto reqHeaders = req.headers.toRepresentation;
    foreach (x; reqHeaders) {
        signRequest.canonicalRequest.headers[x.key] = x.value;
    }
    signRequest.canonicalRequest.payload = requestBody;

    ubyte[] signKey = signingKey(creds.accessKeySecret, dateString, region, service);
    ubyte[] stringToSign = cast(ubyte[])signableString(signRequest);
    auto signature = sign(signKey, stringToSign);

    auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, signRequest.canonicalRequest.headers, signature);
    req.headers["authorization"] = authHeader;
}

class AWSResponse
{
  
    private Json m_body;

    this(HTTPClientResponse response)
    {
        //m_response = response;
        m_body = response.readJson();
        response.dropBody();
        response.destroy();
    }
    
    override string toString()
    {
      return m_body.toString();
    }

    @property Json responseBody() { return m_body; }
}

