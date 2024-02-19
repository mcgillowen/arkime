/* Copyright 2012-2017 AOL Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "arkime.h"

#define OCSFDNSDEBUG 1

LOCAL  char                 *qclasses[256];
LOCAL  char                 *qtypes[256];
LOCAL  char                 *rcodes[16] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMPL", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "11", "12", "13", "14", "15"};
LOCAL  char                 *opcodes[16] = {"QUERY", "IQUERY", "STATUS", "3", "NOTIFY", "UPDATE", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"};

typedef enum ocsf_dns_class
{
    CLASS_IN      =     1,
    CLASS_CS      =     2,
    CLASS_CH      =     3,
    CLASS_HS      =     4,
    CLASS_NONE    =   254,
    CLASS_ANY     =   255,
    CLASS_UNKNOWN = 65280
} OCSFDNSClass_t;

typedef enum ocsf_dns_result_record_type
{
    RESULT_RECORD_ANSWER          =     1,    /* Answer or Prerequisites Record */
    RESULT_RECORD_AUTHORITATIVE   =     2,    /* Authoritative or Update Record */
    RESULT_RECORD_ADDITIONAL      =     3,    /* Additional Record */
    RESULT_RECORD_UNKNOWN         =     4,    /* Unknown Record*/
} OCSFDNSResultRecordType_t;

typedef struct {
    uint8_t            *data[2];
    uint16_t            size[2];
    uint16_t            pos[2];
    uint16_t            len[2];
} OCSFDNSInfo_t;

extern ArkimeConfig_t        config;
LOCAL  int                   ocsfDNSField;

/******************************************************************************/
LOCAL void ocsf_dns_free(ArkimeSession_t *UNUSED(session), void *uw)
{
    OCSFDNSInfo_t            *info          = uw;

    if (info->data[0])
        free(info->data[0]);
    if (info->data[1])
        free(info->data[1]);
    ARKIME_TYPE_FREE(OCSFDNSInfo_t, info);
}
/******************************************************************************/
LOCAL int ocsf_dns_name_element(BSB *nbsb, BSB *bsb)
{
    int nlen = 0;
    BSB_IMPORT_u08(*bsb, nlen);

    if (nlen == 0 || nlen > BSB_REMAINING(*bsb)) {
        return 1;
    }

    int j;
    for (j = 0; j < nlen; j++) {
        register u_char c = 0;
        BSB_IMPORT_u08(*bsb, c);

        if (!isascii(c)) {
            BSB_EXPORT_u08(*nbsb, 'M');
            BSB_EXPORT_u08(*nbsb, '-');
            c = toascii(c);
        }
        if (!isprint(c)) {
            BSB_EXPORT_u08(*nbsb, '^');
            c ^= 0x40;
        }

        BSB_EXPORT_u08(*nbsb, c);
    }

    return 0;
}
/******************************************************************************/
LOCAL uint8_t *ocsf_dns_name(const uint8_t *full, int fulllen, BSB *inbsb, uint8_t *name, int *namelen)
{
    BSB  nbsb;
    int  didPointer = 0;
    BSB  tmpbsb;
    BSB *curbsb;

    BSB_INIT(nbsb, name, *namelen);

    curbsb = inbsb;

    while (BSB_REMAINING(*curbsb)) {
        uint8_t ch = 0;
        BSB_IMPORT_u08(*curbsb, ch);

        if (ch == 0)
            break;

        BSB_EXPORT_rewind(*curbsb, 1);

        if (ch & 0xc0) {
            if (didPointer > 5)
                return 0;
            didPointer++;
            int tpos = 0;
            BSB_IMPORT_u16(*curbsb, tpos);
            tpos &= 0x3fff;

            BSB_INIT(tmpbsb, full + tpos, fulllen - tpos);
            curbsb = &tmpbsb;
            continue;
        }

        if (BSB_LENGTH(nbsb)) {
            BSB_EXPORT_u08(nbsb, '.');
        }

        if (ocsf_dns_name_element(&nbsb, curbsb) && BSB_LENGTH(nbsb))
            BSB_EXPORT_rewind(nbsb, 1); // Remove last .
    }
    *namelen = BSB_LENGTH(nbsb);
    BSB_EXPORT_u08(nbsb, 0);
    return name;
}
/******************************************************************************/
LOCAL void ocsf_dns_parser(ArkimeSession_t *session, int kind, const uint8_t *data, int len)
{

    if (len < 17)
        return;

    int id      = (data[0] << 8 | data[1]);
    int qr      = (data[2] >> 7) & 0x1;
    int opcode  = (data[2] >> 3) & 0xf;
    /*
       int aa      = (data[2] >> 2) & 0x1;
       int tc      = (data[2] >> 1) & 0x1;
       int rd      = (data[2] >> 0) & 0x1;
       int ra      = (data[3] >> 7) & 0x1;
       int z       = (data[3] >> 6) & 0x1;
       int ad      = (data[3] >> 5) & 0x1;
       int cd      = (data[3] >> 4) & 0x1;
    */
    if (opcode > 5)
        return;

    int qd_count = (data[4] << 8) | data[5];                                                          /*number of question records*/
    int an_prereqs_count = (data[6] << 8) | data[7];                                                  /*number of answer or prerequisite records*/
    int ns_update_count = (opcode == 5 || config.parseDNSRecordAll) ? (data[8] << 8) | data[9] : 0;   /*number of authoritative or update recrods*/
    int ar_count = (opcode == 5 || config.parseDNSRecordAll) ? (data[10] << 8) | data[11] : 0;        /*number of additional records*/

    int resultRecordCount [3] = {0};
    resultRecordCount [0] = an_prereqs_count;
    resultRecordCount [1] = ns_update_count;
    resultRecordCount [2] = ar_count;

#ifdef OCSFDNSDEBUG
    LOG("OCSFDNSDEBUG: [Query/Zone Count: %d], [Answer or Prerequisite Count: %d], [Authoritative or Update RecordCount: %d], [Additional Record Count: %d]", qd_count, an_prereqs_count, ns_update_count, ar_count);
#endif

    if (qd_count != 1) {
        arkime_session_add_tag(session, "dns-qdcount-not-1");
        return;
    }

    ArkimeOCSFDNS_t *dns = ARKIME_TYPE_ALLOC0(ArkimeOCSFDNS_t);
    dns->query.packet_uid = id;
    // TODO: Get already existing dns object if packet uid matches

    BSB bsb;
    BSB_INIT(bsb, data + 12, len - 12);

    /* QD Section */
    uint8_t  namebuf[8000];
    int namelen = sizeof(namebuf);
    dns->query.hostname = g_hostname_to_unicode(ocsf_dns_name(data, len, &bsb, namebuf, &namelen));

    if (BSB_IS_ERROR(bsb) || !dns->query.hostname)
        return;

    if (!namelen) {
        dns->query.hostname = (uint8_t *)"<root>";
        namelen = 6;
    }

    unsigned short qtype = 0, qclass = 0 ;
    BSB_IMPORT_u16(bsb, qtype);
    BSB_IMPORT_u16(bsb, qclass);

    if (opcode == 5) { /* Skip Zone records in UPDATE query*/
        if (dns->query.hostname) {
            g_free(dns->query.hostname);
        }
        return;
    }

    if (qclass <= 255 && qclasses[qclass]) {
        dns->query.class = g_strndup(qclasses[qclass], strlen(qclasses[qclass]));
    }

    if (qtype <= 255 && qtypes[qtype]) {
        dns->query.type = g_strndup(qtypes[qtype], strlen(qtypes[qtype]));
    }

    dns->query.opcode_id = opcode;
    dns->query.opcode = g_strndup(opcodes[opcode], strlen(opcodes[opcode]));

    switch(kind) {
    case 0:
        arkime_session_add_protocol(session, "dns");
        break;
    case 1:
        arkime_session_add_protocol(session, "llmnr");
        break;
    case 2:
        arkime_session_add_protocol(session, "mdns");
        break;
    }

    if (qr == 0 && opcode != 5) {
        if (dns->query.hostname) {
            g_free(dns->query.hostname);
        }
        return;
    }

    if (qr != 0) {
        dns->rcode_id    = data[3] & 0xf;
        dns->rcode       = g_strndup(rcodes[dns->rcode_id], strlen(rcodes[dns->rcode_id]));
    } else {
        dns->rcode_id    = -1; // Not a response
    }

    //TODO: Decide on the correct activity_id, query, response or traffic (bidirectional)

    DLL_INIT(t_, &dns->answers);

    int recordType = 0;
    int i;
    for (recordType = RESULT_RECORD_ANSWER; recordType <= RESULT_RECORD_ADDITIONAL; recordType++) {
        int recordNum = resultRecordCount[recordType - 1];
        for (i = 0; BSB_NOT_ERROR(bsb) && i < recordNum; i++) {
            uint8_t  namebuf[8000];
            int namelen = sizeof(namebuf);
            uint8_t *name = ocsf_dns_name(data, len, &bsb, namebuf, &namelen);

            if (BSB_IS_ERROR(bsb) || !name)
                break;

            #ifdef OCSFDNSDEBUG
                LOG("OCSFDNSDEBUG: RR Name=%s", name);
            #endif

            uint16_t antype = 0;
            BSB_IMPORT_u16 (bsb, antype);
            uint16_t anclass = 0;
            BSB_IMPORT_u16 (bsb, anclass);
            uint32_t anttl = 0;
            BSB_IMPORT_u32 (bsb, anttl);
            uint16_t rdlength = 0;
            BSB_IMPORT_u16 (bsb, rdlength);

            if (BSB_REMAINING(bsb) < rdlength) {
                break;
            }

            if (anclass != CLASS_IN) {
                BSB_IMPORT_skip(bsb, rdlength);
                continue;
            }

            if (strcmp(dns->query.hostname, name) != 0) {
                arkime_session_add_tag(session, "dns-question-answer-name-mismatch");
                BSB_IMPORT_skip(bsb, rdlength);
                continue;
            }

            ArkimeOCSFDNSAnswer_t *answer = ARKIME_TYPE_ALLOC0(ArkimeOCSFDNSAnswer_t);

            switch (antype) {
            case OCSFDNS_RR_A: {
                if (rdlength != 4) {
                    BSB_IMPORT_skip(bsb, rdlength);
                    g_free(answer);
                    continue;
                }

                uint8_t *ptr = BSB_WORK_PTR(bsb);
                answer->ipA = ((uint32_t)(ptr[3])) << 24 | ((uint32_t)(ptr[2])) << 16 | ((uint32_t)(ptr[1])) << 8 | ptr[0];
                
                break;
            }
            case OCSFDNS_RR_NS: {
                BSB rdbsb;
                BSB_INIT(rdbsb, BSB_WORK_PTR(bsb), rdlength);

                namelen = sizeof(namebuf);
                name = ocsf_dns_name(data, len, &rdbsb, namebuf, &namelen);

                if (!namelen || BSB_IS_ERROR(rdbsb) || !name) {
                    BSB_IMPORT_skip(bsb, rdlength);
                    g_free(answer);
                    continue;
                }

                #ifdef OCSFDNSDEBUG
                    LOG("OCSFDNSDEBUG: RR_NS Name=%s", name);
                #endif

                answer->nsdname = g_hostname_to_unicode(name);

                break;
            }
            case OCSFDNS_RR_CNAME: {
                BSB rdbsb;
                BSB_INIT(rdbsb, BSB_WORK_PTR(bsb), rdlength);

                namelen = sizeof(namebuf);
                name = ocsf_dns_name(data, len, &rdbsb, namebuf, &namelen);

                if (!namelen || BSB_IS_ERROR(rdbsb) || !name) {
                    BSB_IMPORT_skip(bsb, rdlength);
                    g_free(answer);
                    continue;
                }

                #ifdef OCSFDNSDEBUG
                    LOG("OCSFDNSDEBUG: RR_CNAME Name=%s", name);
                #endif

                answer->cname = g_hostname_to_unicode(name);

                break;
            }
            case OCSFDNS_RR_MX: {
                BSB rdbsb;
                BSB_INIT(rdbsb, BSB_WORK_PTR(bsb), rdlength);
                uint16_t mx_preference = 0;
                BSB_IMPORT_u16(rdbsb, mx_preference);

                namelen = sizeof(namebuf);
                name = ocsf_dns_name(data, len, &rdbsb, namebuf, &namelen);

                if (!namelen || BSB_IS_ERROR(rdbsb) || !name) {
                    BSB_IMPORT_skip(bsb, rdlength);
                    g_free(answer);
                    continue;
                }

                #ifdef OCSFDNSDEBUG
                    LOG("OCSFDNSDEBUG: RR_MX Exchange=%s", name);
                #endif

                answer->mx = ARKIME_TYPE_ALLOC0(ArkimeOCSFDNSMXRDATA_t);
                (answer->mx)->preference = mx_preference;
                (answer->mx)->exchange = g_hostname_to_unicode(name);

                break;
            }
            case OCSFDNS_RR_AAAA: {
                if (rdlength != 16) {
                    BSB_IMPORT_skip(bsb, rdlength);
                    g_free(answer);
                    continue;
                }

                uint8_t *ptr = BSB_WORK_PTR(bsb);

                answer->ipAAAA = g_memdup(ptr, sizeof(struct in6_addr));

                break;
            }
            } /* switch */
            BSB_IMPORT_skip(bsb, rdlength);

            if (anclass <= 255 && qclasses[anclass]) {
                answer->class = g_strndup(qclasses[anclass], strlen(qclasses[anclass]));
            }

            if (antype <= 255 && qtypes[antype]) {
                answer->type = g_strndup(qtypes[antype], strlen(qtypes[antype]));
                answer->type_id = antype;
            }

            answer->ttl = anttl;
            answer->packet_uid = id;
            // TODO: Implement setting the flags

            DLL_PUSH_TAIL(t_, &dns->answers, answer);
        } // record loop
    } // record type loop

    if (!arkime_field_ocsfdns_add(ocsfDNSField, session, dns, resultRecordCount[0]+resultRecordCount[1]+resultRecordCount[2])) {
        arkime_field_ocsfdns_free(dns);
        dns = 0;
    }
}
/******************************************************************************/
LOCAL int ocsf_dns_tcp_parser(ArkimeSession_t *session, void *uw, const uint8_t *data, int len, int which)
{
    OCSFDNSInfo_t *info = uw;
    while (len >= 2) {

        // First packet of request
        if (info->len[which] == 0) {
            int dnslength = ((data[0] & 0xff) << 8) | (data[1] & 0xff);

            if (dnslength < 18) {
                arkime_parsers_unregister(session, uw);
                return 0;
            }

            // Have all the data in this first packet, just parse it
            if (dnslength <= len - 2) {
                ocsf_dns_parser(session, 0, data + 2, dnslength);
                data += 2 + dnslength;
                len -= 2 + dnslength;
                continue;
            }
            // Don't have all the data, will need to save off

            if (info->size[which] == 0) {
                info->size[which] = MAX(1024, dnslength);
                info->data[which] = malloc(info->size[which]);
            } else if (info->size[which] < dnslength) {
                info->data[which] = realloc(info->data[which], dnslength);
                if (!info->data[which]) {
                    arkime_parsers_unregister(session, uw);
                    return 0;
                }
                info->size[which] = dnslength;
            }

            memcpy(info->data[which], data + 2, len - 2);
            info->len[which] = dnslength;
            info->pos[which] = len - 2;
            return 0;
        } else {
            int rem = info->len[which] - info->pos[which];
            if (rem <= len) {
                memcpy(info->data[which] + info->pos[which], data, rem);
                len -= rem;
                data += rem;
                ocsf_dns_parser(session, 0, info->data[which], info->len[which]);
                info->len[which] = 0;
            } else {
                memcpy(info->data[which] + info->pos[which], data, len);
                info->pos[which] += len;
                return 0;
            }
        }
    }
    return 0;
}
/******************************************************************************/
LOCAL void ocsf_dns_tcp_classify(ArkimeSession_t *session, const uint8_t *UNUSED(data), int UNUSED(len), int UNUSED(which), void *UNUSED(uw))
{
    if (/*which == 0 &&*/ session->port2 == 53 && !arkime_session_has_protocol(session, "ocsfdns")) {
        arkime_session_add_protocol(session, "ocsfdns");
        OCSFDNSInfo_t  *info = ARKIME_TYPE_ALLOC0(OCSFDNSInfo_t);
        arkime_parsers_register(session, ocsf_dns_tcp_parser, info, ocsf_dns_free);
    }
}
/******************************************************************************/
LOCAL int ocsf_dns_udp_parser(ArkimeSession_t *session, void *uw, const uint8_t *data, int len, int UNUSED(which))
{
    if (uw == 0 || (session->port1 != 53 && session->port2 != 53)) {
        ocsf_dns_parser(session, (long)uw, data, len);
    }
    return 0;
}
/******************************************************************************/
LOCAL void oscf_dns_udp_classify(ArkimeSession_t *session, const uint8_t *UNUSED(data), int UNUSED(len), int UNUSED(which), void *UNUSED(uw))
{
    arkime_parsers_register(session, ocsf_dns_udp_parser, uw, 0);
}
/******************************************************************************/
void arkime_parser_init()
{

    ocsfDNSField = arkime_field_define("ocsfdns", "notreal",
                                       "ocsfdns", "ocsfdns", "ocsfdns",
                                       "OCSF DNS Queries",
                                       ARKIME_FIELD_TYPE_OCSFDNS, ARKIME_FIELD_FLAG_CNT | ARKIME_FIELD_FLAG_NODB,
                                       (char *)NULL);

    arkime_field_define("ocsfdns", "integer",
                        "ocsfdns.cnt", "OCSF DNS Queries Cnt", "ocsfdnsCnt",
                        "Count of OCSF DNS Queries",
                        0, ARKIME_FIELD_FLAG_FAKE,
                        (char *)NULL);

    arkime_field_define("ocsfdns", "integer",
                        "ocsfdns.responseCode", "Response Code", "ocsfdns.rcode_id",
                        "OCSF DNS Response code",
                        0, ARKIME_FIELD_FLAG_FAKE,
                        (char *)NULL);

    qclasses[1]   = "IN";
    qclasses[2]   = "CS";
    qclasses[3]   = "CH";
    qclasses[4]   = "HS";
    qclasses[255] = "ANY";

    //http://en.wikipedia.org/wiki/List_of_DNS_record_types
    qtypes[1]   = "A";
    qtypes[2]   = "NS";
    qtypes[3]   = "MD";
    qtypes[4]   = "MF";
    qtypes[5]   = "CNAME";
    qtypes[6]   = "SOA";
    qtypes[7]   = "MB";
    qtypes[8]   = "MG";
    qtypes[9]   = "MR";
    qtypes[10]  = "NULL";
    qtypes[11]  = "WKS";
    qtypes[12]  = "PTR";
    qtypes[13]  = "HINFO";
    qtypes[14]  = "MINFO";
    qtypes[15]  = "MX";
    qtypes[16]  = "TXT";
    qtypes[17]  = "RP";
    qtypes[18]  = "AFSDB";
    qtypes[19]  = "X25";
    qtypes[20]  = "ISDN";
    qtypes[21]  = "RT";
    qtypes[22]  = "NSAP";
    qtypes[23]  = "NSAPPTR";
    qtypes[24]  = "SIG";
    qtypes[25]  = "KEY";
    qtypes[26]  = "PX";
    qtypes[27]  = "GPOS";
    qtypes[28]  = "AAAA";
    qtypes[29]  = "LOC";
    qtypes[30]  = "NXT";
    qtypes[31]  = "EID";
    qtypes[32]  = "NIMLOC";
    qtypes[33]  = "SRV";
    qtypes[34]  = "ATMA";
    qtypes[35]  = "NAPTR";
    qtypes[36]  = "KX";
    qtypes[37]  = "CERT";
    qtypes[38]  = "A6";
    qtypes[39]  = "DNAME";
    qtypes[40]  = "SINK";
    qtypes[41]  = "OPT";
    qtypes[42]  = "APL";
    qtypes[43]  = "DS";
    qtypes[44]  = "SSHFP";
    qtypes[46]  = "RRSIG";
    qtypes[47]  = "NSEC";
    qtypes[48]  = "DNSKEY";
    qtypes[49]  = "DHCID";
    qtypes[50]  = "NSEC3";
    qtypes[51]  = "NSEC3PARAM";
    qtypes[52]  = "TLSA";
    qtypes[55]  = "HIP";
    qtypes[99]  = "SPF";
    qtypes[249] = "TKEY";
    qtypes[250] = "TSIG";
    qtypes[252] = "AXFR";
    qtypes[253] = "MAILB";
    qtypes[254] = "MAILA";
    qtypes[255] = "ANY";

    arkime_parsers_classifier_register_port("dns", NULL, 53, ARKIME_PARSERS_PORT_TCP_DST, ocsf_dns_tcp_classify);

    arkime_parsers_classifier_register_port("dns",   (void *)(long)0,   53, ARKIME_PARSERS_PORT_UDP, oscf_dns_udp_classify);
    arkime_parsers_classifier_register_port("llmnr", (void *)(long)1, 5355, ARKIME_PARSERS_PORT_UDP, oscf_dns_udp_classify);
    arkime_parsers_classifier_register_port("mdns",  (void *)(long)2, 5353, ARKIME_PARSERS_PORT_UDP, oscf_dns_udp_classify);

}
