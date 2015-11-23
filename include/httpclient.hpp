#ifndef _HTTPCLIENT_HPP_
#define _HTTPCLIENT_HPP_

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/write.hpp>

#include <json_spirit/json_spirit.h>

namespace {
    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> SSLStream;

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

class SSLIOStreamDevice : public boost::iostreams::device<boost::iostreams::bidirectional> {
    public:
        SSLIOStreamDevice(SSLStream &streamIn, bool fUseSSLIn) : stream(streamIn) {
            fUseSSL = fUseSSLIn;
            fNeedHandshake = fUseSSLIn;
        }

        bool HandleRequest(const std::string /*server*/, const std::string /*port*/, const std::string request, std::string &/*headers*/, bool printheaders = false);

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

    private:
        void handshake(boost::asio::ssl::stream_base::handshake_type role) {
            if (!fNeedHandshake) return;
            fNeedHandshake = false;
            stream.handshake(role);
        }

        std::size_t read_all(boost::system::error_code &ec) {
            handshake(boost::asio::ssl::stream_base::server); // HTTPS servers read first
            if (fUseSSL)
                return boost::asio::read(stream, sb_, boost::asio::transfer_at_least(1), ec);

            return boost::asio::read(stream.next_layer(), sb_, boost::asio::transfer_at_least(1), ec);
        }

        std::size_t read_until(std::string delimeter, boost::system::error_code &ec) {
            handshake(boost::asio::ssl::stream_base::server); // HTTPS servers read first
            if (fUseSSL)
                return boost::asio::read_until(stream, sb_, delimeter, ec);

            return boost::asio::read_until(stream.next_layer(), sb_, delimeter, ec);
        }

        std::size_t write(boost::system::error_code &ec) {
            handshake(boost::asio::ssl::stream_base::client); // HTTPS clients write first
            if (fUseSSL)
                return boost::asio::write(stream, sb_, ec);

            return boost::asio::write(stream.next_layer(), sb_, ec);
        }

        bool connect(const std::string& server, const std::string& port) {
            boost::asio::ip::tcp::resolver resolver(stream.get_io_service());
            boost::asio::ip::tcp::resolver::query query(server.c_str(), port.c_str());
            boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
            boost::asio::ip::tcp::resolver::iterator end;

            if (fUseSSL) {
                certificate_name.clear(); // Initialize for good measure.
                stream.set_verify_mode(boost::asio::ssl::verify_peer);
                stream.set_verify_callback(boost::bind(&SSLIOStreamDevice::verify_certificate, this, _1, _2));
            }

            boost::system::error_code ec = boost::asio::error::host_not_found;
            while (ec && endpoint_iterator != end) {
                stream.lowest_layer().close();
                stream.lowest_layer().connect(*endpoint_iterator++, ec);
            }
            if (ec)
                return false;

            return true;
        }

        bool getHTTPVersion(std::string &/*headers*/, unsigned int &/*status_code*/);
        void extract_headers(std::string &/*headers*/);
        bool verify_certificate(bool /*preverified*/, boost::asio::ssl::verify_context &/*ctx*/);

        bool fNeedHandshake;
        bool fUseSSL;
        SSLStream& stream;
        boost::asio::streambuf sb_;
        std::string certificate_name;
};

/* Grab the html version and status code from our buffer object and append them
 * to a header string. */
bool SSLIOStreamDevice::getHTTPVersion(std::string &headers, unsigned int &status_code) {
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

void SSLIOStreamDevice::extract_headers(std::string &headers) {
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

bool SSLIOStreamDevice::HandleRequest(const std::string server, const std::string port, const std::string request, std::string &headers, bool printheaders) {
    if (!connect(server, port)) {
        printf("SSLIOStreamDevice::HandleRequest : error connecting to server %s on port %s\n", server.c_str(), port.c_str());
        return false;
    }

    std::ostream os(&sb_);
    os << request;

    boost::system::error_code ec;
    size_t sz;
    sz = write(ec);
    if (ec != boost::system::errc::success || sz <= 0) {
        printf("SSLIOStreamDevice::HandleRequest : error writing to request stream %s\n", ec.message().c_str());
        return false;
    }

    sz = read_until("\r\n", ec);
    if (ec != boost::system::errc::success || sz <= 0) {
        printf("SSLIOStreamDevice::HandleRequest : error reading response %s\n", ec.message().c_str());
        return false;
    }

    unsigned int status_code = 0;
    if (!getHTTPVersion(headers, status_code))
        return false;

    /* Read body til EOF (runs in a loop because it may return success with more
     * pending) */
    while (read_all(ec));
    if (ec != boost::asio::error::eof) {
        printf("SSLIOStreamDevice::HandleRequest : error reading body %s\n", ec.message().c_str());
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
bool SSLIOStreamDevice::verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx) {
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    certificate_name += subject_name;
    certificate_name += "\n";

    return preverified;
}

void SSLIOStreamDevice::ReadToString(std::string &strBuffer) {
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

bool SSLIOStreamDevice::ReadToJSON(json_spirit::Object &obj) {
    std::istream is(&sb_);
    json_spirit::Value val;
    if (json_spirit::read(is, val)) {
        obj = val.get_obj();
        return true;
    }

    return false;
}

#endif // _HTTPCLIENT_HPP_
