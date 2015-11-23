#ifdef DEBUG
    #define BOOST_ASIO_ENABLE_HANDLER_TRACKING
#endif

#include <boost/foreach.hpp>

#include <httpclient.hpp>

using namespace std;
using namespace json_spirit;
using boost::asio::ip::tcp;

bool readHTTPSecureToString(boost::asio::io_service &io_service, const string server, const string port, const string request, string &response, bool printheaders) {
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
    context.set_default_verify_paths();
    SSLStream sslStream(io_service, context);
    SSLIOStreamDevice d(sslStream, true);

    string headers;
    if (!d.HandleRequest(server, port, request, headers, printheaders))
        return false;

    if (d.IsBufferEmpty()) {
        printf("readHTTPSecureToString : null message body\n");
        return false;
    }

    d.ReadToString(response);
    return true;
}

bool readHTTPSecureToJSON(boost::asio::io_service &io_service, const string server, const string port, const string request, Object &obj, bool printheaders) {
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
    context.set_default_verify_paths();
    SSLStream sslStream(io_service, context);
    SSLIOStreamDevice d(sslStream, true);

    string headers;
    if (!d.HandleRequest(server, port, request, headers, printheaders))
        return false;

    if (d.IsBufferEmpty()) {
        printf("readHTTPSecureToString : null message body\n");
        return false;
    }

    d.ReadToJSON(obj);
    return true;
}

bool readHTTPInsecureToString(boost::asio::io_service &io_service, const string server, const string port, const string request, string &response, bool printheaders) {
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
    SSLStream sslStream(io_service, context);
    SSLIOStreamDevice d(sslStream, false);

    string headers;
    if (!d.HandleRequest(server, port, request, headers, printheaders))
        return false;

    if (d.IsBufferEmpty()) {
        printf("readHTTPInsecureToString : null message body\n");
        return false;
    }

    d.ReadToString(response);
    return true;
}


bool readHTTPInsecureToJSON(boost::asio::io_service &io_service, const string server, const string port, const string request, Object &obj, bool printheaders) {
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
    SSLStream sslStream(io_service, context);
    SSLIOStreamDevice d(sslStream, false);

    string headers;
    if (!d.HandleRequest(server, port, request, headers, printheaders))
        return false;

    if (d.IsBufferEmpty()) {
        printf("readHTTPInsecureToString : null message body\n");
        return false;
    }

    d.ReadToJSON(obj);
    return true;
}

bool readHTTPToString(const string server, const string port, const string request, string &response, bool secure = false, bool printheaders = false) {
    boost::asio::io_service io_service;
    return secure ? readHTTPSecureToString(io_service, server, port, request, response, printheaders) : readHTTPInsecureToString(io_service, server, port, request, response, printheaders);
}

bool readHTTPToJSON(const string server, const string port, const string request, Object &obj, bool secure = false, bool printheaders = false) {
    boost::asio::io_service io_service;

    return secure ? readHTTPSecureToJSON(io_service, server, port, request, obj, printheaders) : readHTTPInsecureToJSON(io_service, server, port, request, obj, printheaders);
}

int main(int argc, char* argv[]) {
    string url;
    //string response;

    url = "api.github.com";
    stringstream ss1;
    ss1 << "GET /users/IngCr3at1on HTTP/1.1\r\n"
        << "Host: " << url << "\r\n"
        << "Accept: application/vnd.github.v3+json\r\n"
        << "User-Agent: Irrational HTTPC example\r\n"
        << "Connection: close\r\n\r\n"
        ;
/*
    response.clear();
    if (readHTTPToString(url, "https", ss1.str(), response, true))
        printf("%s\n", response.c_str());
*/
    Object obj;
    if (readHTTPToJSON(url, "https", ss1.str(), obj, true)) {
        string name;
        BOOST_FOREACH(Pair_impl<Config_vector<string> > p, obj) {
            if (p.name_ == "name") {
                name = p.value_.get_str();
                break;
            }
        }

        if (!name.empty())
            printf("User name: %s\n", name.c_str());
    }

    return 0;
}
