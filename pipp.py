#!/usr/bin/python
#
# PacketSled Intel Pre Processor for Bro in PacketSled
#
# WHEN          WHAT                                                    WHO
# 10-07-2015    Initial development                                     Aaron Eppert
# 08-02-2017    Adding functionality                                    Aaron Eppert

import os
import re
import sys
import string
from optparse import OptionParser

def escape(c):
    if ord(c) > 31 and ord(c) < 127:
        return c
    c = ord(c)
    if c <= 0xff:
        return r'\x{0:02x}'.format(c)
    elif c <= r'\uffff':
        return r'\u{0:04x}'.format(c)
    else:
        return r'\U{0:08x}'.format(c)


def hex_escape(s):
    return ''.join(escape(c) for c in s)


def write_stderr(msg):
    sys.stderr.write(msg + '\n')


def warning_line(line, *objs):
    out = 'WARNING: Line %d - ' % (int(line)+1)
    for o in objs:
        out += o
    write_stderr(out)


class bro_intel_indicator_return:
    OKAY    = 0
    WARNING = 1
    ERROR   = 2


###############################################################################
# class bro_intel_indicator_type
#
# This class is for handling the "indicator_type" fields within a Bro Intel
# file. Note, each type of field has a specific handler.
#
class bro_intel_indicator_type:
    def __init__(self):
        self.__INDICATOR_TYPE_handler = {'Intel::ADDR':         self.__handle_intel_addr,
                                         'Intel::NET':          self.__handle_intel_net,
                                         'Intel::URL':          self.__handle_intel_url,
                                         'Intel::SOFTWARE':     self.__handle_intel_software,
                                         'Intel::EMAIL':        self.__handle_intel_email,
                                         'Intel::DOMAIN':       self.__handle_intel_domain,
                                         'Intel::USER_NAME':    self.__handle_intel_user_name,
                                         'Intel::FILE_HASH':    self.__handle_intel_file_hash,
                                         'Intel::FILE_NAME':    self.__handle_intel_file_name,
                                         'Intel::CERT_HASH':    self.__handle_intel_cert_hash}

    def __handle_intel_addr(self, indicator):
        ret = (bro_intel_indicator_return.OKAY, None)
        import socket
        try:
            socket.inet_aton(indicator)
        except socket.error:
            ret = (bro_intel_indicator_return.ERROR, 'Invalid IP address')
        return ret

    # In an effort to keep this script minimal and without requiring external
    # libraries, we will verify an Intel::NET simply as:
    #
    # 0 <= octet < 255
    # 0 <= netmask <= 32
    #
    def __handle_intel_net(self, indicator):
        ret = (bro_intel_indicator_return.OKAY, None)
        if '/' in indicator:
            addr, net = indicator.split('/')
            if all([(int(x) >= 0 and int(x) < 255) for x in addr.split('.')]):
                if not (int(net) >= 0 and int(x) <= 32):
                    ret = (bro_intel_indicator_return.ERROR, 'Invalid network block designation')
            else:
                ret = (bro_intel_indicator_return.ERROR, 'Invalid network address')
        else:
            ret = (bro_intel_indicator_return.ERROR, 'Invalid network designation')
        return ret

    # We will call this minimalist, but effective.
    def __handle_intel_url(self, indicator):
        ret = (bro_intel_indicator_return.OKAY, None)

        t_uri_present = re.findall(r'^https?://', indicator)
        if t_uri_present is not None and len(t_uri_present) > 0:
            ret = (bro_intel_indicator_return.WARNING, 'URI present (e.g. http(s)://)')
        else:
            rx = re.compile(r'^[https?://]?'  # http:// or https://
                            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                            r'localhost|'  # localhost...
                            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
                            r'(?::\d+)?'  # optional port
                            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            t = rx.search(indicator)
            if t:
                ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def __handle_intel_email(self, indicator):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid email address')
        rx = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        t_email = re.findall(rx, indicator)
        if len(t_email) > 0:
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def __handle_intel_software(self, indicator):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid software string')
        if len(indicator) > 0:
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def __handle_intel_domain(self, indicator):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid domain name')
        rx = r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'
        t_domain = re.findall(rx, indicator)
        if len(t_domain) > 0:
            if indicator in t_domain[0]:
                ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def __handle_intel_user_name(self, indicator):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid username - %s' % (indicator))
        if len(indicator) > 0:
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def __handle_intel_file_name(self, indicator):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid username length')
        if len(indicator) > 0:
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    # Pretty weak, but should suffice for now.
    def __handle_intel_file_hash(self, indicator):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid hash length')
        valid_hash_len = {32: 'md5',
                          40: 'sha1',
                          64: 'sha256'}
        if valid_hash_len.get(len(indicator), None):
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def __handle_intel_cert_hash(self, indicator):
        return (bro_intel_indicator_return.WARNING,
                'Intel::CERT_HASH - Needs additional validation')

    def verify_indicator_type(self, indicator_type):
        ret = (bro_intel_indicator_return.ERROR, 'Invalid indicator - %s' % (indicator_type))
        it = self.__INDICATOR_TYPE_handler.get(indicator_type, None)
        if it is not None:
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def correlate(self, indicator, indicator_type):
        ret = (bro_intel_indicator_return.WARNING, 'Could not correlate - %s with %s' % (indicator, indicator_type))
        if len(indicator) > 1 and len(indicator_type) > 1:
            h = self.__INDICATOR_TYPE_handler.get(indicator_type, None)
            if h:
                ret = h(indicator)
            else:
                ret = (bro_intel_indicator_return.OKAY, None)
        return ret


###############################################################################
# class bro_data_intel_field_values
#
# This class is for processing the individual Bro Intel fields and verifying
# their validity.
#
# Note, it may be easily expanded via adding entries to self.__VERIFY within
# the class constructor.
#
class bro_data_intel_field_values:
    EMPTY_FIELD_CHAR = '-'
    META_DO_NOTICE = ['T', 'F']

    META_IF_IN = ['-',
                  'Conn::IN_ORIG',
                  'Conn::IN_RESP',
                  'Files::IN_HASH',
                  'Files::IN_NAME',
                  'DNS::IN_REQUEST',
                  'DNS::IN_RESPONSE',
                  'HTTP::IN_HOST_HEADER',
                  'HTTP::IN_REFERRER_HEADER',
                  'HTTP::IN_USER_AGENT_HEADER',
                  'HTTP::IN_X_FORWARDED_FOR_HEADER',
                  'HTTP::IN_URL',
                  'SMTP::IN_MAIL_FROM',
                  'SMTP::IN_RCPT_TO',
                  'SMTP::IN_FROM',
                  'SMTP::IN_TO',
                  'SMTP::IN_RECEIVED_HEADER',
                  'SMTP::IN_REPLY_TO',
                  'SMTP::IN_X_ORIGINATING_IP_HEADER',
                  'SMTP::IN_MESSAGE',
                  'SSL::IN_SERVER_CERT',
                  'SSL::IN_CLIENT_CERT',
                  'SSL::IN_SERVER_NAME',
                  'SMTP::IN_HEADER']

    def __init__(self):
        self.__VERIFY = {'indicator':           self.verify_indicator,
                         'indicator_type':      self.verify_indicator_type,
                         'meta.do_notice':      self.verify_meta_do_notice,
                         'meta.if_in':          self.verify_meta_if_in,
                         'meta.desc':           self.verify_meta_desc,
                         'meta.source':         self.verify_meta_source,
                         'meta.cif_confidence': self.verify_meta_cif_confidence,
                         'meta.url':            self.verify_meta_url,
                         'meta.whitelist':      self.verify_meta_whitelist,
                         'meta.severity':       self.verify_meta_severity,
                         'meta.cif_severity':   self.verify_meta_cif_severity,
                         'meta.cif_impact':     self.verify_meta_cif_impact}

        self.biit = bro_intel_indicator_type()

    def get_verifier(self, v):
        return self.__VERIFY.get(v, self.default)

    def __verify_chars(self, t):
        return all(ord(l) > 31 and ord(l) < 127 and l in string.printable for l in t)

    def __is_ignore_field(self, t):
        return self.EMPTY_FIELD_CHAR in t

    def verify_indicator(self, t):
        ret = (bro_intel_indicator_return.ERROR, 'Invalid indicator - %s' % (t))
        if len(t) > 1 and self.__verify_chars(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def verify_indicator_type(self, t):
        return self.biit.verify_indicator_type(t)

    def correlate_indictor_and_indicator_type(self, i, it):
        return self.biit.correlate(i, it)

    def verify_meta_do_notice(self, t):
        ret = (bro_intel_indicator_return.OKAY, None)
        t_ret = t in bro_data_intel_field_values.META_DO_NOTICE
        if not t_ret:
            ret = (bro_intel_indicator_return.ERROR, 'Invalid do_notice - %s' % (str(t)))
        return ret

    def verify_meta_if_in(self, t):
        ret = (bro_intel_indicator_return.OKAY, None)
        t_ret = t in bro_data_intel_field_values.META_IF_IN
        if not t_ret:
            ret = (bro_intel_indicator_return.ERROR, 'Invalid if_in - %s' % (str(t)))
        return ret

    def verify_meta_cif_confidence(self, t):
        ret = (bro_intel_indicator_return.ERROR, 'Invalid confidence - %s - Needs to be 1-100' % (str(t)))
        try:
            t_int = int(t)
            if isinstance(t_int, (int, long)) and (t_int > 0 and t_int < 100):
                ret = (bro_intel_indicator_return.OKAY, None)
        except ValueError:
            ret = (bro_intel_indicator_return.ERROR, 'Invalid confidence - %s - Needs to be 1-100' % (str(t)))
        return ret

    def verify_meta_desc(self, t):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid desc - %s' % (t))
        if self.__is_ignore_field(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        elif len(t) > 1 and self.__verify_chars(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def verify_meta_source(self, t):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid source - %s' % (t))
        if self.__is_ignore_field(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        elif len(t) > 1 and self.__verify_chars(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def verify_meta_url(self, t):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid url - %s' % (t))
        if self.__is_ignore_field(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        elif len(t) > 1 and self.__verify_chars(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def verify_meta_whitelist(self, t):
        ret = (bro_intel_indicator_return.OKAY, 'Invalid whitelist - %s' % (t))
        if self.__is_ignore_field(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        elif len(t) > 1 and self.__verify_chars(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def verify_meta_severity(self, t):
        ret = (bro_intel_indicator_return.ERROR, 'Invalid severity - %s (valid: 1-10)' % (t))
        try:
            t_int = int(t)
            if isinstance(t_int, (int, long)) and (t_int > 0 and t_int < 10):
                ret = (bro_intel_indicator_return.OKAY, None)
        except ValueError:
            ret = (bro_intel_indicator_return.ERROR, 'Invalid severity - %s  (valid: 1-10)' % (t))
        return ret

    def verify_meta_cif_severity(self, t):
        VALID_SEVERITY = ['-', 'low', 'medium', 'med', 'high']
        ret = (bro_intel_indicator_return.ERROR, 'Invalid cif_severity - %s (valid: %s)' % (t, ','.join(VALID_SEVERITY)))
        if t in VALID_SEVERITY:
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def verify_meta_cif_impact(self, t):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid cif_impact - %s' % (t))
        if self.__is_ignore_field(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        elif len(t) > 1 and self.__verify_chars(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret

    def default(self, t):
        ret = (bro_intel_indicator_return.WARNING, 'Invalid - %s' % (t))
        write_stderr("Running default handler for: %s" % (t))
        if self.__is_ignore_field(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        elif len(t) > 1 and self.__verify_chars(t):
            ret = (bro_intel_indicator_return.OKAY, None)
        return ret


###############################################################################
# class bro_intel_feed_verifier
#
# This is the control class for Bro Intel Feed verification
#
class bro_intel_feed_verifier:
    stock_required_fields = ['indicator',
                             'indicator_type',
                             'meta.source']
    psled_required_fields = ['indicator',
                             'indicator_type',
                             'meta.source',
                             'meta.desc']
    field_header_designator = '#fields'
    feed_rx = r'([\S]+)'
    feed_sep_rx = r'(\t)+'

    header_fields = []

    def __init__(self, options):
        self.feed_file = options.feed_file
        self.__feed_header_found = False
        self.__num_of_fields = 0
        self.required_fields = bro_intel_feed_verifier.stock_required_fields

    def __make_one_indexed(self, l):
        return map(lambda x: x+1, l)

    def __is_start_of_feed(self, l):
        ret = False
        if len(l) >= 2:
            if l[0] == self.field_header_designator:
                ret = True
        return ret

    def __are_header_fields_valid(self, l):
        ret = False
        _fields_found = []
        if l[0] == self.field_header_designator:
            for index, item in enumerate(l):
                if index == 0:
                    continue
                if item in self.required_fields:
                    _fields_found.append(item)
                self.header_fields.append(item)

            t_list_diff = list(set(self.required_fields) - set(_fields_found))
            if len(t_list_diff) == 0:
                ret = True
            else:
                warning_line(0, 'Fields missing: %s' % (','.join(t_list_diff)))
        return ret

    def __count_fields(self, l):
        return len(l) - 1

    ##
    # <0 - Too few fields
    #  0 - Proper field count
    # >0 - Too many fields
    ##
    def __verify_field_count(self, l):
        return len(l) - self.__num_of_fields

    def __verify_non_space(self, offset, l):
        ret = True

        r = [i for i, x in enumerate(l) if x == ' ']
        if len(r) > 0:
            warning_line(offset, 'Invalid empty field, offset %s' % (self.__make_one_indexed(r)))
            ret = False
        return ret

    def __get_field_contents(self, l):
        return l.split('\t')

    def __verify_field_sep(self, offset, l, is_header=False):
        ret = True
        field_seps = re.findall(self.feed_sep_rx, l, re.IGNORECASE)
        __field_total = self.__num_of_fields

        if is_header:
            __field_total += 1

        if len(field_seps) >= __field_total:
            warning_line(offset, 'Excess field separators found')
            ret = False

        for index, item in enumerate(field_seps):
            for s in item:
                if s != '\t':
                    warning_line(offset, 'Field separator incorrect in field offset %d' %
                                 (self.__make_one_indexed(index)))
                    ret = False
        return ret

    def __verify_header(self, index, l):
        ret = False
        contents = self.__get_field_contents(l)
        if self.__is_start_of_feed(contents) and self.__are_header_fields_valid(contents):
            if not self.__feed_header_found:
                self.__num_of_fields = self.__count_fields(contents)
                if self.__verify_field_sep(index, l, is_header=True):
                    ret = True
                    self.__feed_header_found = True
                else:
                    write_stderr("Invalid field separator found in header. Must be a tab.")
            else:
                warning_line(index, "Duplicate header found")
        return ret

    def __verify_fields(self, index, content):
        ret = True
        _fields_to_process = {}
        validator = bro_data_intel_field_values()

        #
        # Not thrilled about this, but we need it to pull out correlatable fields
        # since, order of the actual feed fields aren't guaranteed. Ugly for now,
        # but workable and can likely be optimized shortly.
        #
        for content_index, t in enumerate(content):
            _fields_to_process[self.header_fields[content_index]] = t

        for k in _fields_to_process:
            r = validator.get_verifier(k)(_fields_to_process[k])

            if not r:
                if all(ord(l) > 31 and ord(l) < 127 and l in string.printable for l in k):
                    t_line = str(_fields_to_process[k])
                    t_line = hex_escape(t_line)
                    warning_line(index, 'Invalid entry \"%s\" for column \"%s\"' %
                                 (str(t_line), str(k)))
                else:
                    warning_line(index, 'Unprintable character found for column \"%s\"' %
                                 (str(k)))
                ret = False
                break

        if ret:
            # Special case to verify indicator with indicator_type
            c = validator.correlate_indictor_and_indicator_type(
                _fields_to_process['indicator'],
                _fields_to_process['indicator_type'])

            if not c:
                warning_line(index,
                             'Indicator type \"%s\" does not correlate with indicator: \"%s\"' %
                             (_fields_to_process['indicator_type'],
                              _fields_to_process['indicator']))
                ret = False
        return ret

    def __verify_entry(self, index, l):
        ret = False
        contents = self.__get_field_contents(l)
        _content_field_count = self.__verify_field_count(contents)
        _warn_str = None

        if _content_field_count == 0:
            if self.__verify_field_sep(index, l) and self.__verify_non_space(index, contents) and self.__verify_fields(index, contents):
                ret = True
        elif _content_field_count > 0:
            _warn_str = 'Invalid number of fields - Found: %d, Header Fields: %d - Look for: EXTRA fields or tab seperators' % (len(contents), self.__num_of_fields)
        elif _content_field_count < 0:
            _warn_str = 'Invalid number of fields - Found: %d, Header Fields: %d - Look for: EMPTY fields' % (len(contents), self.__num_of_fields)

        if _warn_str:
            warning_line(index, _warn_str)

        return ret

    def load_feed(self, feed):
        with open(feed) as f:
            for line in f:
                t_line = line.rstrip('\n')
                t_line = line.rstrip('\r')
                if len(t_line):
                    yield t_line

    def verify(self, header_only=False):
        for index, l in enumerate(self.load_feed(self.feed_file)):
            # Check the header
            if index == 0:
                if not self.__verify_header(index, l):
                    warning_line(index, "Invalid header")
                    sys.exit(2)
            elif header_only is True:
                break
            else:
                if not self.__verify_entry(index, l):
                    sys.exit(3)

    def header_exists(self, entry):
        return entry in self.header_fields


###############################################################################
# main()
###############################################################################
def main():
    parser = OptionParser()
    parser.add_option('-f', '--file',    dest='feed_file', help='Bro Intel Feed to Append')
    parser.add_option('-n', '--new',     dest='new_file',  help='File to write appended feed data')
    parser.add_option('--meta-desc',     dest='meta_desc',  help='Verify Intel meets PacketSled requirements')
    parser.add_option('--meta-severity', dest='meta_severity', type='int', help='Warn ONLY on errors, continue processing and report')
    (options, args) = parser.parse_args()

    if len(sys.argv) < 4:
        parser.print_help()
        sys.exit(1)

    bifv = bro_intel_feed_verifier(options)
    bifv.verify(header_only=True)

    if options.meta_desc is not None:
        if bifv.header_exists('meta.desc') is True:
            print 'ERROR: meta.desc already exists'
            sys.exit(1)

    if options.meta_severity is not None:
        if bifv.header_exists('meta.severity') is True:
            print 'ERROR: meta.desc already exists'
            sys.exit(1)

    if options.new_file is None:
        print 'ERROR: Please supply a --new/-n file argument'
        parser.print_help()
        sys.exit(1)

    if options.feed_file is not None and os.path.exists(options.feed_file):

        new_out = open(options.new_file, 'w')
        for index, l in enumerate(bifv.load_feed(options.feed_file)):
            # Check the header
            t_out = l
            if index == 0:
                if options.meta_desc is not None:
                    t_out += '\tmeta.desc'

                if options.meta_severity is not None:
                    t_out += '\tmeta.severity'
            else:
                if options.meta_desc is not None:
                    t_out += '\t' + options.meta_desc

                if options.meta_severity is not None:
                    t_out += '\t' + str(options.meta_severity)

            new_out.write(t_out + '\n')
        new_out.close()

###############################################################################
# __name__ checking
###############################################################################
if __name__ == '__main__':
    main()
