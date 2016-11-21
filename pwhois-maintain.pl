#!/usr/bin/env perl

use strict;
use warnings;
use Getopt::Long;
use LWP::Simple;
use Template;

use lib 'lib';
use Net::Whois::Raw;

use constant {
    GTLD_URL        => 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt',
    NOTFOUND_DOMAIN => '3b43763b-09b87hidaf',
};

sub usage() {
    die "usage:
    $0 --check-for-new-gtlds [--cache-dir /path/to/whois-cachedir] [--max-new num]
        --check-for-new-gtlds - try to find whois servers for gTLDs which are not in Data.pm yet
        --cache-dir - cache dir for whois responses, cache lifetime is 24 hrs
        --max-new - stop when specified number of new gTLDs found\n";
}

GetOptions(
    'check-for-new-gtlds' => \my $check_for_new_gtlds,
    'cache-dir=s'         => \my $cache_dir,
    'max-new=i'           => \my $max_new,
) || usage;

$Net::Whois::Raw::TIMEOUT = 10;
if ($cache_dir) {
    $Net::Whois::Raw::CACHE_DIR = $cache_dir;
    $Net::Whois::Raw::CACHE_TIME = 24*60; # one day
}

if ($check_for_new_gtlds) {
    my @new;
    
    # get TLD list
    my $raw_list = get(GTLD_URL) or die "Can't get TLD list";
    
    for my $tld (split /\n/, $raw_list) {
        # skip empty lines and comments
        next if $tld =~ /^\s*#/;
        $tld =~ s/\s//g;
        next if !$tld;
        
        # check if we already have such TLD
        $tld = uc $tld;
        next if exists $Net::Whois::Raw::Data::servers{$tld};
        
        # get whois server for TLD using whois.iana.org
        print "new TLD found: $tld\n";
        print "\tdetermining whois server\n";
        my $tld_info = eval { whois($tld, 'whois.iana.org', 'QRY_FIRST') }
            or warn "can't receive whois response for `$tld'\n" and next;
        my ($whois_server) = $tld_info =~ /^\s*whois:\s*(\S+)/im
            or warn "can't find whois server for `$tld'" and next;
        
        my $notfound = 0;
        my $notfound_pat;
        unless ( exists $Net::Whois::Raw::Data::notfound{$whois_server} ) {
            # receive "not found" response, so we can make "not found" pattern
            print "\tdetermining `not found` response\n";
            $notfound = eval { whois(NOTFOUND_DOMAIN.".$tld", $whois_server, 'QRY_LAST') }
                or warn "can't receive `not found` response for `$tld`\n";
                
            if ($notfound) {
                $notfound =~ s/^\s+//;
                # try to suggest not found pattern
                ($notfound_pat) = $notfound =~ /([^\n]+)/;
                $notfound_pat =~ s/\s+$//;
                my $fix_re = NOTFOUND_DOMAIN.'.*';
                $notfound_pat =~ s/$fix_re//i;
                $notfound_pat =~ s/([\[\].+'\(\)?*\{\}])/\\$1/g; # used in regexp
                
                # prevent duplicates
                $Net::Whois::Raw::Data::notfound{$whois_server} = 0;
            }
        }
        
        push @new, {
            tld          => $tld,
            whois_server => $whois_server,
            notfound     => $notfound,
            notfound_pat => $notfound_pat,
        };
        
        if ($max_new && @new == $max_new) {
            print "--max-new limit exceeded\n";
            last;
        }
    }
    
    unless (@new) {
        print "No new GTLD records found. Data.pm is up to date\n";
        exit;
    }
    
    # tlds with not found message at the top
    @new = sort { 
        $a->{whois_server} cmp $b->{whois_server} or
        defined($b->{notfound}) <=> defined($a->{notfound}) or
        ($b->{notfound}&&1||0) <=> ($a->{notfound}&&1||0)
    } @new;
    
    # generate HTML
    my $tpl = Template->new;
    $tpl->process(\*DATA, {
        new    => \@new,
        source => scalar do { local $/; open my $fh, '<:utf8', 'lib/Net/Whois/Raw/Data.pm' or die $!; <$fh> },
    }, \my $html) or die "Can't process template: ", $tpl->error;
    
    open my $fh, '>:utf8', 'new-gtlds.html'
        or die "open > new-gtlds.html: $!";
    print $fh $html;
    close $fh;
    
    print "Done! Now open `new-gtlds.html' in your favorite browser.\n";
}
else {
    usage;
}

__DATA__

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <title>New gTLDs found</title>
        <script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
        <style>
            textarea {
                white-space: pre;
                overflow-wrap: normal;
                overflow-x: scroll;
            }
            
            tr.border_bottom td {
                border-bottom:1pt solid black;
                padding: 10px 0px 10px 0px;
            }
            
            td.whois_column {
                position: relative;
            }
            
            .accept_block {
                position: absolute;
                top: 0px;
                right: 10px;
            }
        </style>
    </head>
    <body>
        <script>
            $(function() {
                $('#process').click(function() {
                    var new_tlds = [];
                    var not_selected = 0;
                    var server_empty = 0;
                    var first = true;
                    
                    // push all input into array
                    $('#result tr').each(function() {
                        if (first) {
                            first = false;
                            return;
                        }
                        
                        var self = $(this);
                        var tld = self.find('td[data-id="tld"]').text();
                        var td_whois = self.find('td[data-id="whois_server"]');
                        var whois_server = td_whois.find('input[type="text"]').val();
                        var selected = td_whois.find('input[type="radio"]:checked').val();
                        var notfound_pat = self.find('td[data-id="notfound"] input[data-id="notfound_pat"]').val();
                        
                        new_tlds.push({
                           tld: tld,
                           whois_server: whois_server,
                           notfound_pat: notfound_pat,
                           selected: selected 
                        });
                        
                        if (!selected) not_selected++;
                        if (!whois_server) server_empty++;
                    })
                    
                    // check for user errors
                    if (server_empty || not_selected) {
                        if ( !confirm((server_empty ? server_empty + ' whois servers empty, ' : '') +
                                      (not_selected ? not_selected + ' items not processed, ' : '') +
                                      'are u sure u want to continue? All of this tlds will be skipped') ) {
                            return;
                        }
                    }
                    
                    this.disabled = true;
                    
                    // get servers from perl sourcecode
                    var source = $('#source').val();
                    var match = source.match(/our\s+%servers\s*=\s*qw\(((?:.|\n)+?)\);/);
                    if (!match) {
                        alert('Unexpected fail: can not find %servers in Data.pm');
                        return;
                    }
                    
                    var raw_servers = match[1];
                    var raw_servers_groups = raw_servers.split(/\n[ \t]*\n/);
                    var servers_groups = [];
                    for (var rsg in raw_servers_groups) {
                        servers_groups.push( parse_str_group( raw_servers_groups[rsg] ) );
                    }
                    
                    // get not found patterns from perl sourcecode
                    match = source.match(/our\s+%notfound\s*=\s*\(\n((?:.|\n)+?)\);/);
                    if (!match) {
                        alert('Unexpected fail: can not find %notfound in Data.pm');
                        return;
                    }
                    
                    var raw_notfound = match[1];
                    var raw_notfound_groups = raw_notfound.split(/\n[ \t]*\n/);
                    // always push to last nf group
                    var notfound_group = parse_str_group( raw_notfound_groups[raw_notfound_groups.length - 1] );
                    
                    // process
                    for (var tld_r in new_tlds) {
                        tld_r = new_tlds[tld_r];
                        
                        if (tld_r.selected != 'accept' || !tld_r.whois_server) {
                            continue;
                        }
                        
                        // whois server
                        inject_new_whois_server(tld_r.tld, tld_r.whois_server, servers_groups);
                        // not found pattern
                        if (tld_r.notfound_pat)
                            inject_new_notfound_pattern(tld_r.notfound_pat, tld_r.whois_server, notfound_group);
                    }
                    
                    // combine back to string
                    for (var i in servers_groups) {
                        raw_servers_groups[i] = combine_str_group( servers_groups[i] );
                    }
                    raw_servers = raw_servers_groups.join('\n\n');
                    
                    raw_notfound_groups[raw_notfound_groups.length - 1] = combine_str_group( notfound_group, true );
                    raw_notfound = raw_notfound_groups.join('\n\n');
                    
                    // replace in source code
                    source = source.replace(/our\s+%servers\s*=\s*qw\(\s*(?:.|\n)+?\);/, 'our %servers = qw(\n' + raw_servers + '\n);');
                    source = source.replace(/our\s+%notfound\s*=\s*\(\s*(?:.|\n)+?\);/, 'our %notfound = (\n' + raw_notfound + '\n);');
                    $('#source').val(source);
                    
                    $('#source_block').show();
                    $('html, body').animate({
                        scrollTop: $("#source_block").offset().top
                    }, 2000);
                })
            })
            
            // combine back str group to string
            function combine_str_group(group, is_hash_style) {
                var records = [];
                for (var r in group.records) {
                    r = group.records[r];
                    
                    if (is_hash_style) {
                        records.push(
                            "    " + r.left +
                                      ' '.repeat(group.indent - r.left.length - 3) +
                                      "=> " + r.right
                        );
                    }
                    else {
                        records.push(
                            '    ' + r.left +
                                     ' '.repeat(group.indent - r.left.length) +
                                     r.right
                        );
                    }
                }
                
                if (!is_hash_style && group.affected) records.sort();
                
                return records.join('\n');
            }
            
            // inject new not found pattern in the right place
            function inject_new_notfound_pattern(pat, server, group) {
                // check indent width: '' + spaces + =>
                if (server.length + 6 > group.indent) {
                    group.indent = server.length + 6;
                }
                group.records.push({
                    left: "'" + server + "'",
                    right: "'" + pat + "',"
                })
            }
            
            //  check is server name a equals server name b, at least partly
            function server_names_cmp(a, b) {
                // server.whois.ru.com -> ['server', 'whois.ru.com']
                var parts_a = a.split('.');
                var len = parts_a.length - 1;
                var tld_finish = len - 1;
                for (; tld_finish > 0; tld_finish--) {
                    if (parts_a[tld_finish] == 'nic' || parts_a[tld_finish].length > 3)
                        break;
                }
                parts_a[tld_finish] += '.' + parts_a.splice(tld_finish+1).join('.');
                
                // same for b
                var parts_b = b.split('.');
                len = parts_b.length - 1;
                tld_finish = len - 1;
                for (; tld_finish > 0; tld_finish--) {
                    if (parts_b[tld_finish] == 'nic' || parts_b[tld_finish].length > 3)
                        break;
                }
                parts_b[tld_finish] += '.' + parts_b.splice(tld_finish+1).join('.');
                
                // now cmp from the end
                var len_a = parts_a.length;
                var len_b = parts_b.length;
                var i, j = 1;
                for (i=len_a-1; i>=0 && j<=len_b; i--, j++) {
                    if (parts_a[i] != parts_b[len_b-j]) break;
                }
                
                // return rating
                return (len_a-i-1)/len_a * (j-1)/len_b;
            }
            
            // inject new tld server in the right place
            function inject_new_whois_server(tld, server, groups) {
                var rating = {};
                
                for (var i=0; i<groups.length; i++) {
                    rating[i] = 0;
                    for (var r in groups[i].records) {
                        rating[i] += server_names_cmp(groups[i].records[r].right, server);
                    }
                }
                
                var srk = Object.keys(rating).sort(function(a, b) { return rating[b] - rating[a]; });
                if (rating[ srk[0] ] == 0) {
                    // no appropriate group found, create new one
                    
                    // try to get indent from last group to look cool
                    var indent = groups[groups.length-1].indent;
                    if (tld.length + 2 > indent) {
                        indent = tld.length + 2;
                    }
                    
                    groups.push({
                        indent: indent,
                        affected: false,
                        records: [{
                            left: tld,
                            right: server
                        }]
                    });
                }
                else {
                    // group found
                    var group = groups[ srk[0] ];
                    if (tld.length + 2 > group.indent) {
                        group.indent = tld.length + 2;
                    }
                    group.affected = true;
                    
                    group.records.push({
                        left: tld,
                        right: server
                    });
                }
            }
            
            // split str group to left and right parts
            // with indent width info saved
            function parse_str_group(str) {
                str = $.trim(str);
                var lines = str.split('\n');
                var result = {
                    indent: null,
                    affected: false,
                    records: []
                };
                
                for (var line in lines) {
                    line = $.trim(lines[line]);
                    if (!result.indent) {
                        var parts = adequate_split(line, /\s+/, 3);
                        result.indent = line.length - parts[parts.length-1].length;
                    }
                    
                    var parts = adequate_split(line, /\s+/, 3);
                    result.records.push({
                        left: parts[0],
                        right: parts[parts.length-1] // =>
                    });
                }
                
                return result;
            }
            
            // "sds dsfds dfd dfd".split(/\s+/, 3) -> ['sds', 'dsfds', 'dfd']
            // JavaScript are u kidding me?
            function adequate_split(str, pat, limit) {
                var res = [];
                var i;
                for (i = 0; i < limit-1; i++) {
                    var match;
                    if (match = str.match(pat)) {
                        res.push(str.substring(0, match.index));
                        str = str.substring(match.index+match[0].length);
                    }
                    else {
                        res.push(str);
                        break;
                    }
                }
                if (i == limit-1) res.push(str);
                
                return res;
            }
        </script>
        <table style="width: 100%" id="result">
            <tr style="text-align: left;">
                <th>TLD</th><th>Whois server</th><th>Not Found pattern</th>
            </tr>
            [% FOREACH i IN new %]
                <tr class="border_bottom">
                    <td data-id="tld"><b>[% i.tld %]</b></td>
                    <td data-id="whois_server" class="whois_column">
                        <div class="accept_block">
                            <label><input type="radio" name="[% i.tld %]" value="accept"> Accept</label><br>
                            <label><input type="radio" name="[% i.tld %]" value="skip"> Skip</label>
                        </div>
                        <input type="text" value="[% i.whois_server %]">
                    </td>
                    <td data-id="notfound">
                        [% IF i.notfound or not i.notfound.defined  %]
                            <div>
                                <input data-id="notfound_pat" type="text" style="width: 400px" value="[% FILTER html %][% i.notfound_pat %][% END %]">
                            </div>
                            [% IF i.notfound %]
                                <textarea style="width: 700px; height: 300px;">[% FILTER html %][% i.notfound %][% END %]</textarea>
                            [% ELSE %]
                                couldn't receive response from the whois server
                            [% END %]
                        [% ELSE %]
                            <i>Not Found pattern already in Data.pm or above</i>
                        [% END %]
                    </td>
                </tr>
            [% END %]
        </table>
        <div style="text-align: center; margin: 20px;"><button id="process">PROCESS!</button></div>
        <div style="display: none" id="source_block">
            <center>Now copy and paste code below to <i>lib/Net/Whois/Raw/Data.pm</i></center>
            <textarea style="width:100%; height: 500px;" id="source">[% FILTER html %][% source %][% END %]</textarea>
        </div>
    </body>
</html>
