#ifndef _HTTPCLIENT_HPP_
#define _HTTPCLIENT_HPP_

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>

#include <json_spirit/json_spirit.h>

namespace {
    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

    bool valid_status(unsigned int status_code, std::string headers, bool printheaders = false) {
        switch(status_code) {
            case 200:
                break;
            case 201:
                if (printheaders)
                    printf("%s\n", headers.c_str());
                /* Do not break or return allowing the printheaders to work on
                 * all cases over 200 */
            case 301:
                if (!printheaders)
                    printf("getstatus : response returned with status code 301 : moved permanently\n");
                return false;
            case 403:
                if (!printheaders)
                    printf("getstatus : response returned with status code 403 : forbidden\n");
                return false;
            default:
                if (printheaders && status_code < 200)
                    printf("%s\n", headers.c_str());
                if (!printheaders)
                    printf("getstatus : response returned with status code %d\n", status_code);
                return false;
        }

        return true;
    }
} // namespace

class HTTPClient {
    public:
        HTTPClient(boost::asio::io_service &io_service,
                    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
                  : socket_(io_service)
                  {
                      boost::asio::connect(socket_, endpoint_iterator);
                  }

        bool HandleRequest(boost::asio::ip::tcp::resolver::query /*query*/, std::string /*request*/, std::string &/*headers*/, bool /*printheaders*/);
        /** Read the contents of the buffer into a string. */
        void ReadToString(std::string &/*strBuffer*/);
        /** Read the contents of the buffer into a JSON object. */
        bool ReadToJSON(json_spirit::Object &/*obj*/);
        /** Check if a client buffer object is empty. */
        bool IsBufferEmpty() {
            if (sb_.in_avail() <= 0)
                return true;

            return false;
        }

    protected:
        boost::asio::streambuf sb_;

        bool getHTTPVersion(std::string &/*headers*/, unsigned int &/*status_code*/);
        void extract_headers(std::string &/*headers*/);

    private:
        boost::asio::ip::tcp::socket socket_;
};

class HTTPClientSecure : public HTTPClient {
    public:
        HTTPClientSecure(boost::asio::io_service &io_service,
                          boost::asio::ssl::context &context,
                          boost::asio::ip::tcp::resolver::iterator endpoint_iterator,
                          std::string request)
                        : HTTPClient(io_service, endpoint_iterator),
                          socket_(io_service, context)
                        {
                            certificate_name.clear(); // Initialize for good measure.
                            socket_.set_verify_mode(boost::asio::ssl::verify_peer);
                            socket_.set_verify_callback(boost::bind(&HTTPClientSecure::verify_certificate, this, _1, _2));
                            boost::asio::connect(socket_.lowest_layer(), endpoint_iterator);
                            socket_.handshake(ssl_socket::client);
                        }
        /* Overwrite HandleRequest to use the ssl_socket on socket calls instead
         * of a standard socket. */
        bool HandleRequest(boost::asio::ip::tcp::resolver::query /*query*/, std::string /*request*/, std::string &/*headers*/, bool /*printheaders*/);

    private:
        ssl_socket socket_;
        std::string certificate_name;
        bool verify_certificate(bool /*preverified*/, boost::asio::ssl::verify_context &/*ctx*/);
};

/* Grab the html version and status code from our buffer object and append them
 * to a header string. */
bool HTTPClient::getHTTPVersion(std::string &headers, unsigned int &status_code) {
    std::string html_version;
    std::istream is(&sb_);

    is >> html_version;
    is >> status_code;

    if (html_version.substr(0, 4) != "HTTP") {
        printf("HTTPClient::getHTTPVersion : invalid response from server\n");
        return false;
    }

    headers = html_version;
    headers += " ";
    headers += std::to_string(status_code);

    return true;
}

void HTTPClient::extract_headers(std::string &headers) {
    std::istream is(&sb_);
    std::string header;
    unsigned int i = 0;
    while (getline(is, header) && header != "\r") {
        if (i != 0)
            headers += "\n";

        headers += header;
        i++;
    }
}

bool HTTPClient::HandleRequest(boost::asio::ip::tcp::resolver::query query, std::string request, std::string &headers, bool printheaders) {
    std::ostream os(&sb_);
    os << request;

    boost::system::error_code ec;
    boost::asio::write(socket_, sb_, ec);
    if (ec != boost::system::errc::success) {
        printf("HTTPClient::HandleRequest : error writing to request stream %s\n", ec.message().c_str());
        return false;
    }

    boost::asio::read_until(socket_, sb_, "\r\n", ec);
    if (ec != boost::system::errc::success) {
        printf("HTTPClient::HandleRequest : error reading response %s\n", ec.message().c_str());
        return false;
    }

    unsigned int status_code = 0;
    if (!getHTTPVersion(headers, status_code))
        return false;

    // Read body til EOF
    while (boost::asio::read(socket_, sb_, boost::asio::transfer_at_least(1), ec));
    if (ec != boost::asio::error::eof) {
        printf("HTTPClient::HandleRequest : error reading body %s\n", ec.message().c_str());
        return false;
    }

    extract_headers(headers);

    if (!valid_status(status_code, headers, printheaders))
        return false;

    if (printheaders)
        printf("%s\n", headers.c_str());

    return true;
}

/* If we have -printheaders defined go ahead and print certificate names on
 * secure connections, otherwise just return default verification. */
bool HTTPClientSecure::verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx) {
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    certificate_name += subject_name;
    certificate_name += "\n";

    return preverified;
}

bool HTTPClientSecure::HandleRequest(boost::asio::ip::tcp::resolver::query query, std::string request, std::string &headers, bool printheaders) {
    std::ostream os(&sb_);
    os << request;

    if (printheaders)
        printf("%s\n", certificate_name.c_str());

    boost::system::error_code ec;
    boost::asio::write(socket_, sb_, ec);
    if (ec != boost::system::errc::success) {
        printf("HTTPClientSecure::HandleRequest : error writing to request stream %s\n", ec.message().c_str());
        return false;
    }

    boost::asio::read_until(socket_, sb_, "\r\n", ec);
    if (ec != boost::system::errc::success) {
        printf("HTTPClientSecure::HandleRequest : error reading response %s\n", ec.message().c_str());
        return false;
    }

    unsigned int status_code = 0;
    if (!getHTTPVersion(headers, status_code))
        return false;

    // Read body til EOF
    while (boost::asio::read(socket_, sb_, boost::asio::transfer_at_least(1), ec));
    if (ec != boost::asio::error::eof) {
        printf("HTTPClientSecure::HandleRequest : error reading body %s\n", ec.message().c_str());
        return false;
    }

    extract_headers(headers);

    if (!valid_status(status_code, headers, printheaders))
        return false;

    if (printheaders)
        printf("%s\n", headers.c_str());

    return true;
}

void HTTPClient::ReadToString(std::string &strBuffer) {
    std::istream is(&sb_);
    std::string strLine;
    unsigned int i = 0;
    while(getline(is, strLine)) {
        if (i != 0)
            strBuffer += "\n";

        strBuffer += strLine;
        i++;
    }
}

bool HTTPClient::ReadToJSON(json_spirit::Object &obj) {
    std::istream is(&sb_);
    json_spirit::Value val;
    if (json_spirit::read(is, val)) {
        obj = val.get_obj();
        return true;
    }

    return false;
}

#endif // _HTTPCLIENT_HPP_
