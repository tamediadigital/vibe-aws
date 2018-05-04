module vibe.aws.s3;

import vibe.d;
import vibe.core.stream;

import vibe.aws.aws;
import vibe.aws.credentials;
import vibe.aws.sigv4;

import std.typecons: Tuple, tuple;

enum StorageClass: string
{
    STANDARD = "STANDARD",
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY",
    GLACIER = "GLACIER"
}

struct BucketListResult
{
    static struct S3Resource
    {
        static struct Owner
        {
            string id;
            string displayName;
        }

        string key;
        string lastModfied;
        string etag;
        ulong size;
        Owner owner;
        StorageClass storageClass;
    }

    string name;
    string prefix;
    string marker;
    string nextMarker;
    S3Resource[] resources;
    string[] commonPrefixes;
    uint maxKeys;
    bool isTruncated;
}

auto listFilesRecursive(S3 client, string path = null)
{
    if(!path.empty && !path.endsWith("/"))
        path ~= "/";
    return S3Resources(client, null, path);
}

auto listFiles(S3 client, string path = null)
{
    if(!path.empty && !path.endsWith("/"))
        path ~= "/";
    return S3Resources(client, "/", path);
}

auto listFolders(S3 client, string path = null)
{
    if(!path.empty && !path.endsWith("/"))
        path ~= "/";
    return S3Prefixes(client, "/", path);
}

struct S3Resources
{
    import std.range.primitives;
    mixin _S3Common;

    auto front() @property
    {
        assert(!empty);
        return res.resources.front;
    }

    auto empty() const @property
    {
        return res.resources.empty;
    }

    auto popFront()
    {
        assert(!empty);
        res.resources.popFront;
        if(empty && res.isTruncated)
        {
            next;
        }
    }

}

struct S3Prefixes
{
    import std.range.primitives;
    mixin _S3Common;

    auto front() @property
    {
        assert(!empty);
        return res.commonPrefixes.front;
    }

    auto empty() const @property
    {
        return res.commonPrefixes.empty;
    }

    auto popFront()
    {
        assert(!empty);
        res.commonPrefixes.popFront;
        if(empty && res.isTruncated)
        {
            next;
        }
    }
}

private mixin template _S3Common()
{
    private S3 client;
    private BucketListResult res;
    private string delimiter;
    private string prefix;
    private uint maxKeys;

    private void next()
    {
        res = client.list(delimiter, prefix, res.nextMarker, maxKeys);
    }

    @disable this();

    this(S3 client, string delimiter, string prefix, uint maxKeys = 0)
    {
        this.client = client;
        this.delimiter = delimiter;
        this.prefix = prefix;
        this.maxKeys = maxKeys;
        next();
    }

    auto save() @property
    {
        return this;
    }
}

class S3 : RESTClient
{
    private string bucket;

    this(string bucket, string region, AWSCredentialSource credsSource, ClientConfiguration config = ClientConfiguration())
    {
        this.bucket = bucket;
        enforce(region.length, "AWS region should be defined.");
        super(bucket ~ ".s3-" ~ region ~ ".amazonaws.com", region, "s3", credsSource, config);
    }

    auto list(string delimiter = null, string prefix = null, string marker = null, uint maxKeys = 0)
    {
        assert(maxKeys <= 1000);

        import memutils.all;
        import std.stdio;
        import std.conv;

        InetHeaderMap headers;
        string[string] queryParameters;

        if (delimiter !is null)
            queryParameters["delimiter"] = delimiter;

        if (prefix !is null)
            queryParameters["prefix"] = prefix;

        if (marker !is null)
            queryParameters["marker"] = marker;

        if (maxKeys)
            queryParameters["max-keys"] = maxKeys.to!string;

        auto resp = doRequest(HTTPMethod.GET, "/", queryParameters, headers);
        auto response = readXML(resp);
        resp.dropBody();
        resp.destroy();

        BucketListResult result;
        result.name = response.querySelector("ListBucketResult Name").innerText;
        result.prefix = response.querySelector("ListBucketResult Prefix").innerText;
        result.marker = response.querySelector("ListBucketResult Marker").innerText;
        result.maxKeys = response.querySelector("ListBucketResult MaxKeys").innerText.to!uint;
        result.isTruncated = response.querySelector("ListBucketResult IsTruncated").innerText.toLower.to!bool;

        if (result.isTruncated)
            result.nextMarker = response.querySelector("ListBucketResult NextMarker").innerText;

        auto entries = response.querySelector("ListBucketResult Contents");

        result.resources.reserve = 1000;
        foreach(node; entries.children)
        {
            BucketListResult.S3Resource entry;
            BucketListResult.S3Resource.Owner owner;

            entry.key = node.querySelector("Key").innerText;
            entry.lastModfied = node.querySelector("LastModified").innerText;
            entry.etag = node.querySelector("ETag").innerText;
            entry.size = node.querySelector("Size").innerText.to!ulong;
            import std.conv;
            entry.storageClass = node.querySelector("StorageClass")[0].innerText.to!StorageClass;

            result.resources.assumeSafeAppend ~= entry;
        }
        result.resources.reserve = result.resources.length;

        result.commonPrefixes.reserve = 1000;
        auto prefixes = response.querySelectorAll("ListBucketResult CommonPrefixes Prefix");
        foreach(node; prefixes)
            result.commonPrefixes.assumeSafeAppend ~= node.innerText;
        result.commonPrefixes.reserve = result.commonPrefixes.length;

        return result;
    }

    void upload(
        string resource,
        RandomAccessStream input,
        string contentType = "application/octet-stream",
        StorageClass storageClass = StorageClass.STANDARD,
        size_t chunkSize = 512*1024,
        )
    {
        InetHeaderMap headers;
        headers["Content-Type"] = contentType;
        headers["x-amz-storage-class"] = storageClass.to!string;
        string[] signedHeaders = ["x-amz-storage-class"];
        auto httpResp = doUpload(HTTPMethod.PUT,
            resource, null, headers, signedHeaders, input, chunkSize);
        httpResp.dropBody();
        httpResp.destroy();
    }

    /++
    On_failure: aborts multipart upload.
    +/
    void multipartUpload(
        string resource,
        scope InputStream input,
        InetHeaderMap headers = InetHeaderMap.init,
        string contentType = "application/octet-stream",
        StorageClass storageClass = StorageClass.STANDARD, 
        SysTime expires = SysTime.init,
        size_t chunkSize = 512*1024,
        size_t partSize = 5*1024*1024,
        )
    {
        import std.array: appender, uninitializedArray;
        import std.algorithm.comparison: min;
        logDebug("multipartUpload for %s ...", resource);
        enforce(partSize >= 5 * 1024 * 1024, "multipartUpload: minimal allowed part size is 5 MB.");
        auto id = startMultipartUpload(resource, headers, contentType, storageClass, expires);
        scope(failure)
        {
            logWarn("aborting multipart upload for resource=%s, uploadId=%s", resource, id);
            try
            {
                abortMultipartUpload(resource, id);
            }
            catch(Exception e)
            {
                logWarn(e.msg);
            }
        }

        auto buf = uninitializedArray!(ubyte[])(partSize);
        auto etags = appender!(Tuple!(string, size_t)[]);

        size_t least = input.leastSize;
        for(size_t part = 1;;part++)
        {
            size_t length;
            do
            {
                auto newLength = least + length;
                if(newLength > buf.length)
                    newLength = buf.length;
                input.read(buf[length .. newLength]);
                length = newLength;
                least = input.leastSize;
            }
            while(least && length < buf.length);
            logDebug("buf.length = %s", buf.length);
            logDebug("least = %s", least);
            logDebug("multipartUpload: sending %s bytes for part %s ...", length, part);
            auto etag = uploadPart(resource, id, part, createMemoryStream(buf[0 .. length], false), contentType, chunkSize);
            etags.put(tuple(etag, part));
            if(least == 0)
                break;
        }
        enforce(etags.data, "At least one part should be uploaded.");
        completeMultipartUpload(resource, id, etags.data);
    }

    string uploadPart(
        string resource,
        string id,
        size_t part,
        RandomAccessStream input,
        string contentType = "application/octet-stream",
        size_t chunkSize = 512*1024,
        )
    {
        string[string] queryParameters = [
            "partNumber": part.to!string,
            "uploadId": id,
        ];
        InetHeaderMap headers;
        headers["Content-Type"] = contentType;
        logDebug("uploadPart: doUpload ...");
        auto httpResp = doUpload(HTTPMethod.PUT, resource, queryParameters, headers, null, input, chunkSize);
        logDebug("uploadPart: doUpload finished.");
        httpResp.dropBody();
        auto etag = httpResp.headers["ETag"];
        httpResp.destroy();
        logDebug("uploadPart: finished.");
        return etag;
    }

    string startMultipartUpload(
        string resource,
        InetHeaderMap headers = InetHeaderMap.init,
        string contentType = "application/octet-stream", 
        StorageClass storageClass = StorageClass.STANDARD,
        SysTime expires = SysTime.init,
        )
    {
        headers["Content-Type"] = contentType;
        headers["x-amz-storage-class"] = storageClass.to!string;
        string[] signedHeaders = ["x-amz-storage-class"];
        if(expires != SysTime.init)
        {
            expires.fracSecs = expires.fracSecs.init;
            headers["Expires"] = expires.toISOString; // HTTP format is different. So, we need to check if it is works.
        }
        auto httpResp = doRequest(HTTPMethod.POST, resource, ["uploads":null], headers);
        scope(exit)
        {
            httpResp.dropBody();
            httpResp.destroy();
        }
        auto document = readXML(httpResp);
        auto id = document.querySelector("InitiateMultipartUploadResult UploadId").innerText;
        return id;
    }

    void completeMultipartUpload(
        string resource,
        string id,
        in Tuple!(string, size_t)[] parts,
        InetHeaderMap headers = InetHeaderMap.init,
        )
    {
        import std.format;
        import std.array: appender;
        auto app = appender!(char[]);
        app.put(`<CompleteMultipartUpload>`);
        FormatSpec!char fmt;
        foreach(ref part; parts)
        {
            app.put(`<Part><PartNumber>`);
            app.formatValue(part[1], fmt);
            app.put(`</PartNumber><ETag>`);
            app.put(part[0]);
            app.put(`</ETag></Part>`);
        }
        app.put(`</CompleteMultipartUpload>`);
        auto httpResp = doRequest(HTTPMethod.POST, resource, ["uploadId":id], headers, cast(ubyte[])app.data);
        httpResp.dropBody();
        httpResp.destroy();
    }

    void abortMultipartUpload(string resource, string id)
    {
        auto httpResp = doRequest(HTTPMethod.DELETE, resource, ["uploadId":id], InetHeaderMap.init);
        httpResp.dropBody();
        httpResp.destroy();
    }

    void info(string resource, scope void delegate(scope HTTPClientResponse) del,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        auto httpResp = doRequest(HTTPMethod.HEAD, resource, queryParameters, headers);
        scope(exit)
        {
            httpResp.dropBody();
            httpResp.destroy();
        }
        del(httpResp);
    }

    void download(string resource, scope void delegate(scope HTTPClientResponse) del,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        auto httpResp = doRequest(HTTPMethod.GET, resource, queryParameters, headers);
        scope(exit)
        {
            httpResp.dropBody();
            httpResp.destroy();
        }
        del(httpResp);
    }

    /++
    Returns:
        Response headers list, which has type  DictionaryList!(string,false,12L,false)
    +/
    auto download(string resource, scope void delegate(scope InputStreamProxy) del,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        typeof(HTTPClientResponse.headers) ret;
        download(resource, (scope HTTPClientResponse resp) {
            ret = resp.headers;
            del(resp.bodyReader);
        }, queryParameters, headers);
        return ret;
    }

    /// ditto
    auto download(OutputStream)(string resource, scope OutputStream stream,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        return download(resource, (scope InputStreamProxy input) { input.pipe(stream); }, queryParameters, headers);
    }

    /// ditto
    auto download(string resource, string saveTo,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        auto file = openFile(saveTo, FileMode.createTrunc);
        scope(exit)
            file.close();
        return download(resource, file, queryParameters, headers);
    }
}
