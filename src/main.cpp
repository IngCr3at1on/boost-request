#ifdef DEBUG
    #define BOOST_ASIO_ENABLE_HANDLER_TRACKING
#endif

#include <boost/foreach.hpp>

#include <httpclient.hpp>

using namespace std;
using namespace json_spirit;
using boost::asio::ip::tcp;

bool readHTTPSecureToString(boost::asio::io_service &io_service, tcp::resolver::iterator endpoint_iterator, tcp::resolver::query query, string request, string &response, bool printheaders) {
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
    context.set_default_verify_paths();
    HTTPClientSecure c(io_service, context, endpoint_iterator, request);

    string headers;
    if (!c.HandleRequest(query, request, headers, printheaders))
        return false;

    if (c.IsBufferEmpty()) {
        printf("readHTTPSecureToString : null message body\n");
        return false;
    }

    c.ReadToString(response);
    return true;
}

bool readHTTPSecureToJSON(boost::asio::io_service &io_service, tcp::resolver::iterator endpoint_iterator, tcp::resolver::query query, string request, Object &obj, bool printheaders) {
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
    context.set_default_verify_paths();
    HTTPClientSecure c(io_service, context, endpoint_iterator, request);

    string headers;
    if (!c.HandleRequest(query, request, headers, printheaders))
        return false;

    if (c.IsBufferEmpty()) {
        printf("readHTTPSecureToString : null message body\n");
        return false;
    }

    c.ReadToJSON(obj);
    return true;
}

bool readHTTPInsecureToString(boost::asio::io_service &io_service, tcp::resolver::iterator endpoint_iterator, tcp::resolver::query query, string request, string &response, bool printheaders) {
    HTTPClient c(io_service, endpoint_iterator);

    string headers;
    if (!c.HandleRequest(query, request, headers, printheaders))
        return false;

    if (c.IsBufferEmpty()) {
        printf("readHTTPInsecureToString : null message body\n");
        return false;
    }

    c.ReadToString(response);
    return true;
}

bool readHTTPInsecureToJSON(boost::asio::io_service &io_service, tcp::resolver::iterator endpoint_iterator, tcp::resolver::query query, string request, Object &obj, bool printheaders) {
    HTTPClient c(io_service, endpoint_iterator);

    string headers;
    if (!c.HandleRequest(query, request, headers, printheaders))
        return false;

    if (c.IsBufferEmpty()) {
        printf("readHTTPInsecureToString : null message body\n");
        return false;
    }

    c.ReadToJSON(obj);
    return true;
}

bool readHTTPToString(tcp::resolver::query query, string request, string &response, bool secure = false, bool printheaders = false) {
    boost::asio::io_service io_service;
    tcp::resolver resolver(io_service);
    tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    return secure ? readHTTPSecureToString(io_service, endpoint_iterator, query, request, response, printheaders) : readHTTPInsecureToString(io_service, endpoint_iterator, query, request, response, printheaders);
}

bool readHTTPToJSON(tcp::resolver::query query, string request, Object &obj, bool secure = false, bool printheaders = false) {
    boost::asio::io_service io_service;
    tcp::resolver resolver(io_service);
    tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    return secure ? readHTTPSecureToJSON(io_service, endpoint_iterator, query, request, obj, printheaders) : readHTTPInsecureToJSON(io_service, endpoint_iterator, query, request, obj, printheaders);
}

int main(int argc, char* argv[]) {
    string url = "api.github.com";
    stringstream ss1;
    ss1 << "GET /users/IngCr3at1on HTTP/1.1\r\n"
        << "Host: " << url << "\r\n"
        << "Accept: application/vnd.github.v3+json\r\n"
        << "User-Agent: Irrational HTTPC example\r\n"
        << "Connection: close\r\n\r\n"
        ;

    Object obj;
    tcp::resolver::query query1(url, "https");
    if (readHTTPToJSON(query1, ss1.str(), obj, true)) {
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
