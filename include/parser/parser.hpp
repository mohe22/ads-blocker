#pragma once
#include <expected>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include "common.hpp"

namespace DNS::Parser{
    class Name {
        public:
            // decode: handles both cases internally
            //   → plain labels: reads normally
            //   → 0xC0 pointer: jumps and follows, caller doesn't need to know
            static std::expected<std::string, Error>
            decode(const uint8_t* data, size_t len, size_t&offset) noexcept;

            // encode: handles both cases internally
            //   → no table: writes plain labels
            //   → table given: writes pointer if name was seen before
            static std::expected<std::vector<uint8_t>, Error>
            encode(const std::string& name,
                        std::unordered_map<std::string, uint16_t>* table,
                        uint16_t baseOffset) noexcept;
    };


    /*
     *  The raw 12-byte header that starts every DNS packet.
     *  Both queries and responses share the exact same layout.
     *
     *      id       → copied from query into response (client matches them)
     *      qr       → 0 = query, 1 = response
     *      opcode   → almost always QUERY (0)
     *      aa       → 1 = server is authoritative for this zone
     *      tc       → 1 = message was truncated, retry over TCP
     *      rd       → 1 = client wants recursive resolution
     *      ra       → 1 = server supports recursion
     *      ad       → 1 = DNSSEC verified (authentic data)
     *      cd       → 1 = DNSSEC checking disabled
     *      rcode    → NOERROR / NXDOMAIN / SERVFAIL etc.
     *
     *      qdcount  → how many Questions follow
     *      ancount  → how many Answer RRs follow
     *      nscount  → how many Authority RRs follow
     *      arcount  → how many Additional RRs follow
     */
    class Header {
        public:
            uint16_t getRawFlags() const noexcept {
                uint16_t flags = 0;

                flags |= (static_cast<uint16_t>(qr_)                  << 15);  // bit 15
                flags |= (static_cast<uint16_t>(opcode_) & 0xF)       << 11;   // bits 14-11
                flags |= (static_cast<uint16_t>(aa_)                  << 10);  // bit 10
                flags |= (static_cast<uint16_t>(tc_)                  <<  9);  // bit 9
                flags |= (static_cast<uint16_t>(rd_)                  <<  8);  // bit 8
                flags |= (static_cast<uint16_t>(ra_)                  <<  7);  // bit 7
                // bit 6 = Z (reserved, always 0)
                flags |= (static_cast<uint16_t>(ad_)                  <<  5);  // bit 5
                flags |= (static_cast<uint16_t>(cd_)                  <<  4);  // bit 4
                flags |= (static_cast<uint16_t>(rcode_) & 0xF);                // bits 3-0

                return flags;
            }
            void setId(const uint16_t& id) noexcept { id_ = id;}
            const uint16_t& getId() const noexcept { return id_;}

            void setQr(const bool& qr) noexcept { qr_ = qr;}
            bool isQr() const noexcept { return qr_;}

            void setOpcode(const OpCode& opcode) noexcept { opcode_ = opcode;}
            const OpCode& getOpcode() const noexcept { return opcode_;}

            void setAa(bool aa) noexcept {aa_=aa;};
            bool isAa() const noexcept { return aa_;}

            void setTc(bool tc) noexcept {tc_=tc;};
            bool isTc() const noexcept { return tc_;}

            void setRd(bool rd) noexcept {rd_=rd;};
            bool isRd() const noexcept { return rd_;}

            void setRa(bool ra) noexcept {ra_=ra;};
            bool isRa() const noexcept { return ra_;}

            void setAd(bool ad) noexcept {ad_=ad;};
            bool isAd() const noexcept { return ad_;}

            void setCd(bool cd) noexcept {cd_=cd;};
            bool isCd() const noexcept { return cd_;}

            void setRcode(const RCode& rcode) noexcept {rcode_=rcode;};
            const RCode& getRcode() const noexcept { return rcode_;}

            void setQuestions(const uint16_t& qdcount) noexcept {qdcount_=qdcount;};
            const uint16_t& getQuestions() const noexcept { return qdcount_;}

            void setAnswers(const uint16_t& ancount) noexcept {ancount_=ancount;};
            const uint16_t& getAnswers() const noexcept { return ancount_;}

            void setAuthorities(const uint16_t& nscount) noexcept {nscount_=nscount;};
            const uint16_t& getAuthorities() const noexcept { return nscount_;}

            void setAdditionals(const uint16_t& arcount) noexcept {arcount_=arcount;};
            const uint16_t& getAdditionals() const noexcept { return arcount_;}

            static std::expected<Header,Error> decode(const uint8_t*buffer,size_t len);

            std::expected<std::vector<uint8_t>, Error> encode() const noexcept ;

            const void print() const noexcept;
        private:
            uint16_t id_;
            bool    qr_;
            OpCode  opcode_;
            bool    aa_;
            bool    tc_;
            bool    rd_;
            bool    ra_;
            bool    ad_;
            bool    cd_;
            RCode   rcode_;

            uint16_t qdcount_;   // number of questions
            uint16_t ancount_;   // number of answer RRs
            uint16_t nscount_;   // number of authority RRs
            uint16_t arcount_;   // number of additional RRs
    };



    /*
        qname  = "google.com"
        qtype  = A (1)
        qclass = IN (1)
     */
    class Question{
        public:
            bool isA()    const { return qtype_ == QType::A;    }
            bool isAAAA() const { return qtype_ == QType::AAAA; }
            bool isAny()  const { return qtype_ == QType::ANY;  }

            void setName(const std::string&name) noexcept {qname_=name;};
            const std::string& getName() const noexcept {return qname_;};

            void setQtype(const QType& type) noexcept {qtype_ = type;};
            const QType& getType() const noexcept { return qtype_ ;};

            void setQclass(const QClass& qclass) noexcept {qclass_ = qclass;};
            const QClass& getClass() const noexcept { return qclass_ ;};
            void print() const noexcept;
            static std::expected<Question,Error> decode(const uint8_t* data, size_t len, size_t& offset)  noexcept;
            std::expected<std::vector<uint8_t>, Error>
            encode(std::unordered_map<std::string, uint16_t>* table,
                             uint16_t baseOffset)  const noexcept ;
        private:
            std::string qname_;
            QType qtype_{QType::A};
            QClass qclass_{QClass::IN_};
    };
    /*
     *  Holds one answer/authority/additional entry:
     *
     *      name     = "google.com"
     *      type     = A
     *      class    = IN
     *      ttl      = 300
     *      rdlength = 4
     *      rdata    = {142, 250, 80, 46}
     *
     *  The same struct is reused for all three sections:
     *      Message::answers      (ANCOUNT records)
     *      Message::authority    (NSCOUNT records)
     *      Message::additional   (ARCOUNT records)
     *
     *  'rdata' is kept as raw bytes — interpret it based on 'type':
     *      A     (1)  → 4 bytes  IPv4
     *      AAAA  (28) → 16 bytes IPv6
     *      CNAME (5)  → encoded domain name
     *      MX    (15) → 2 byte preference + encoded domain name
     *      TXT   (16) → 1 byte length + string (repeatable)
     *      NS    (2)  → encoded domain name
     */
    class  ResourceRecord {
        public:

        const std::string& getName()        const noexcept { return name_; }
        const QType&              getType()        const noexcept { return type_; }
        const QClass&             getRclass()      const noexcept { return rclass_; }
        const uint32_t&           getTtl()         const noexcept { return ttl_; }
        const uint16_t&           getRdlength()    const noexcept { return rdlength_; }
        const std::vector<uint8_t>& getRdata() const noexcept { return rdata_; }

        // Setters
        void setName   (const std::string& name)        noexcept { name_ = name; }
        void setType   (const QType& type)                     noexcept { type_ = type; }
        void setRclass (const QClass& rclass)                  noexcept { rclass_ = rclass; }
        void setTtl    (const uint32_t& ttl)                   noexcept { ttl_ = ttl; }
        void setRdlength(const uint16_t& rdlength)             noexcept { rdlength_ = rdlength; }
        void setRdata  (const std::vector<uint8_t>& rdata) noexcept { rdata_ = rdata; }

        static std::expected<ResourceRecord, Error>
        decode(const uint8_t* data, size_t len, size_t& offset) noexcept;

        std::expected<std::vector<uint8_t>, Error>
        encode(std::unordered_map<std::string, uint16_t>* table,
                               uint16_t baseOffset)  const noexcept ;
        private:
            std::string name_;           // owner name  e.g. "google.com"
            QType type_;                 // record type e.g. QType::A
            QClass rclass_;              // almost always QClass::IN
            uint32_t ttl_;               // seconds until expiry
            uint16_t rdlength_;          // byte length of rdata
            std::vector<uint8_t> rdata_; // raw record data

    };

    /*
     *  A bag that holds everything in one packet — the header +
     *  all the questions + all the records. It doesn't parse anything,
     *  it just groups them:
     *
     *      header      → id, flags, counts
     *      questions   → vector<Question>       (usually just 1)
     *      answers     → vector<ResourceRecord> (the actual IPs etc.)
     *      authority   → vector<ResourceRecord> ("go ask this NS instead")
     *      additional  → vector<ResourceRecord> (glue records)
     *
     *  One Message = one UDP datagram (query or response).
     *  Parser::parse(buf, len) fills this. Parser::encode(msg) writes it back.
     */
    class Message{
        public:
            // Getters
            Header&                  getHeader()     noexcept { return header_; }
            const std::vector<Question>&        getQuestions()  const noexcept { return questions_; }
            const std::vector<ResourceRecord>&  getAnswers()    const noexcept { return answers_; }
            const std::vector<ResourceRecord>&  getAuthority()  const noexcept { return authority_; }
            const std::vector<ResourceRecord>&  getAdditional() const noexcept { return additional_; }

            // Setters
            void setHeader    (const Header& header)                    noexcept { header_    = header; }
            void setQuestions (const std::vector<Question>& questions)  noexcept { questions_ = questions; }
            void setAnswers   (const std::vector<ResourceRecord>& answers)    noexcept { answers_   = answers; }
            void setAuthority (const std::vector<ResourceRecord>& authority)  noexcept { authority_ = authority; }
            void setAdditional(const std::vector<ResourceRecord>& additional) noexcept { additional_ = additional; }

            void addQuestion  (const Question& q)        { questions_.push_back(q); }
            void addAnswer    (const ResourceRecord& rr) { answers_.push_back(rr); }
            void addAuthority (const ResourceRecord& rr) { authority_.push_back(rr); }
            void addAdditional(const ResourceRecord& rr) { additional_.push_back(rr); }
        private:
            Header                      header_;
            std::vector<Question>       questions_;
            std::vector<ResourceRecord> answers_;
            std::vector<ResourceRecord> authority_;
            std::vector<ResourceRecord> additional_;
    };


    class MessageParser  {
            public:

            static std::expected<Message,DNS::Error> parse(const uint8_t* data, size_t len);

            std::expected<std::vector<uint8_t>, DNS::Error>
            static encode(Message& msg) noexcept;
    };
}
