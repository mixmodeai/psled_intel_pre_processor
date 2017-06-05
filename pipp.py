#!/usr/bin/python
#
# PacketSled Intel Pre Processor for Bro in PacketSled
#
# WHEN          WHAT                                               WHO
# 10-7-2015     Initial development                                Aaron Eppert
#

import os
import re
import sys
import string
from optparse import OptionParser

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
        return (len(l) - 1)

    ##
    # <0 - Too few fields
    #  0 - Proper field count
    # >0 - Too many fields
    ##
    def __verify_field_count(self, l):
        return (len(l) - self.__num_of_fields)

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
                    warning_line(offset, 'Field separator incorrect in field offset %d' % (self.__make_one_indexed(index)))
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
                    warning("Invalid field separator found in header. Must be a tab.")
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
                    warning_line(index, 'Invalid entry \"%s\" for column \"%s\"' % (str(t_line), str(k)))
                else:
                    warning_line(index, 'Unprintable character found for column \"%s\"' % (str(k)))
                ret = False
                break

        if ret:
            # Special case to verify indicator with indicator_type
            c = validator.correlate_indictor_and_indicator_type(_fields_to_process['indicator'],
                                                                _fields_to_process['indicator_type'])

            if not c:
                warning_line(index, 'Indicator type \"%s\" does not correlate with indicator: \"%s\"' % (_fields_to_process['indicator_type'], _fields_to_process['indicator']))
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
