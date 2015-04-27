#!/usr/bin/perl
# 
# @APPLE_LICENSE_HEADER_START@ 
#
# Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
#
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this
# file.
#
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
#
# @APPLE_LICENSE_HEADER_END@
#
# Require needed libraries
#
# A very simple perl web server used by Streaming Admin Server

use warnings;

if ($^O eq "MSWin32") {
	eval "use Config";
	$activeperl_required_message = "\r\n\r\nActivePerl 5.8.0 or higher is required in order to run the Darwin Streaming Server web-based administration.\r\nPlease download it from http://www.activeperl.com/ and install it.\r\n\r\n";
	die $activeperl_required_message if ($Config{"PERL_API_REVISION"} + ($Config{"PERL_API_VERSION"} * 0.1) < 5.8);
}
 
# Require needed libraries
package streamingadminserver;
use Socket;
use POSIX;
use Sys::Hostname;

eval "use Net::SSLeay";

$ssl_available = 0;
if (!$@) { #if no error, go
	$use_ssl = 1;
	$ssl_available = 1; # can be set to 0 if a valid cert isn't present
						# this check is done after the config is read in
	# These functions only exist for SSLeay 1.0
	eval "Net::SSLeay::SSLeay_add_ssl_algorithms()";
	eval "Net::SSLeay::load_error_strings()";
	if (defined(&Net::SSLeay::X509_STORE_CTX_get_current_cert) &&
	    defined(&Net::SSLeay::CTX_load_verify_locations) &&
	    defined(&Net::SSLeay::CTX_set_verify)) {
		$client_certs = 1;  #Y
	}
}

# Get streamingadminserver's perl path and location
$streamingadminserver_path = $0;	#D:\GitHub\DarwinStreamingServer\webadmin\admin-win.pl
open(SOURCE, $streamingadminserver_path);  <SOURCE> =~ /^#!(\S+)/;
$perl_path = $1;  close(SOURCE);	#/usr/bin/perl
@streamingadminserver_argv = @ARGV;

if($^O eq "MSWin32") {
	$defaultConfigPath = "C:/Program Files/Darwin Streaming Server/streamingadminserver.conf";
}

$debug = 0;
# Find and read config file
	if (@ARGV < 1) {
		$conf = $defaultConfigPath;
	} elsif(@ARGV == 1) {
		if($ARGV[0] eq "-d") {
			$conf = $defaultConfigPath;
			$debug = 1;
		} else {
			&usage($defaultConfigPath);
			exit;
		}
	} elsif(@ARGV == 2) {
		if(($ARGV[0] eq "-cd") || ($ARGV[0] eq "-dc")) {
			$debug = 1;
		} elsif($ARGV[0] ne "-c") {
			&usage($defaultConfigPath);
			exit;
		}
		if($^O eq "MSWin32") {
			$conf = $ARGV[1];	}
	} else {
		&usage($defaultConfigPath);
		exit;
	}


	#readfile and put into   $config
	if(!open(CONF, $conf)) { # C:/Program Files/Darwin Streaming Server/streamingadminserver.conf
		if($conf ne $defaultConfigPath) { die "Failed to open config file $conf : $!";	}
	} else {
		while(<CONF>) {
			chomp;
			if (/^#/ || !/\S/) { 
				next;
			}
			/^([^=]+)=(.*)$/;
			$name = $1; $val = $2;
			$name =~ s/^\s+//g; $name =~ s/\s+$//g;
			$val =~ s/^\s+//g; $val =~ s/\s+$//g;
			$config{$name} = $val;
		}
		close(CONF);
	}

if($^O eq "MSWin32") {
	%vital = ("port", 1220,
	  "sslport", 1240,
	  "root", "C:/Program Files/Darwin Streaming Server/AdminHtml",
	  "plroot", "C:\\Program Files\\Darwin Streaming Server\\Playlists\\",
	  "server", "QTSS 5.5 Admin Server/1.0",
	  "index_docs", "index.html parse_xml.cgi index.htm index.cgi",
	  "addtype_html", "text/html",
      "addtype_htm", "text/html",
	  "addtype_txt", "text/plain",
	  "addtype_gif", "image/gif",
	  "addtype_jpg", "image/jpeg",
	  "addtype_jpeg", "image/jpeg",
	  "addtype_cgi", "internal/cgi",
	  "addtype_mov", "video/quicktime",
	  "addtype_js", "application/x-javascript",
	  "realm", "QTSS Admin Server",
	  "qtssIPAddress", "localhost",
	  "qtssPort", "554",
	  "qtssName", "C:/Program Files/Darwin Streaming Server/DarwinStreamingServer.exe",
	  "qtssAutoStart", "1",
      "logfile", "C:/Program Files/Darwin Streaming Server/Logs/streamingadminserver.log",
	  "log", "1",
	  "logclear", "0",
	  "logtime", "168",
	  "messagesfile", "messages",
	  "gbrowse", "0",
	  "ssl", "0",
	  "crtfile", "C:/Program Files/Darwin Streaming Server/streamingadminserver.pem",
	  "keyfile", "C:/Program Files/Darwin Streaming Server/streamingadminserver.pem",
	  #"keypasswordfile", "",
	  "qtssQTPasswd", "C:/Program Files/Darwin Streaming Server/qtpasswd.exe",
	  "qtssPlaylistBroadcaster", "c:\\Program Files\\Darwin Streaming Server\\PlaylistBroadcaster.exe",
	  "qtssMP3Broadcaster", "c:\\Program Files\\Darwin Streaming Server\\MP3Broadcaster.exe",
	  "helpurl", "http://helpqt.apple.com/dssWebAdminHelpR3/dssWebAdmin.help/DSSHelp.htm",
	  "qtssAdmin", "streamingadmin",
  	  "cacheMessageFiles", "0",
	  #"pidfile", "C:/Program Files/Darwin Streaming Server/streamingadminserver.pid"
	  );
}

foreach $v (keys %vital) {
	if ((!defined($config{$v})) || ($config{$v} eq "")) {
		if ($vital{$v} eq "") {
		    die "Missing config option $v";
		}
		$config{$v} = $vital{$v};
	}
}

# Check if valid ssl cert and key files are present
# if not, then set $ssl_available to 0
# For now, just check for the existance of the files
if(($config{'crtfile'} eq "") || ($config{'keyfile'} eq "") || !(-e $config{'crtfile'}) || !(-e $config{'keyfile'}) ){
	$ssl_available = 0;  #Yes
}

if($config{'qtssIPAddress'} eq "localhost") {
	$config{'qtssIPAddress'} = inet_ntoa(INADDR_LOOPBACK);
}

$passwordfile = $config{'keypasswordfile'};
$keypassword = "";
if(defined($passwordfile) && ($passwordfile ne "")){ #No
	if(open(PASSFILE, $passwordfile)) {
		read(PASSFILE, $keypassword, -s $passwordfile);
		close(PASSFILE);
	}
}

# init days and months for http_date
@weekday = ( "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" );
@month = ( "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" );

# Change dir to the server root
chdir($config{'root'}); #C:/Program Files/Darwin Streaming Server/AdminHtm

# Setup SSL if possible and if requested
# Setup SSL no matter what - otherwise dynamic switching between http and https won't work!

if (!$config{'ssl'}) {
	$use_ssl = 0;	}

if ($ssl_available) { #No
	$ssl_ctx = Net::SSLeay::CTX_new() || die "Failed to create SSL context : $!";
	$client_certs = 0 if (!$config{'ca'} || !%certs);
	if ($client_certs) {  #Yes
		Net::SSLeay::CTX_load_verify_locations(	$ssl_ctx, $config{'ca'}, "");
		Net::SSLeay::CTX_set_verify( $ssl_ctx, &Net::SSLeay::VERIFY_PEER, \&verify_client);
	}
}

# read config into mime
foreach $k (keys %config) {
    if ($k !~ /^addtype_(.*)$/) { next; }
    $mime{$1} = $config{$k};
}

# get the time zone
if ($config{'log'}) { #YES
	local(@gmt, @lct, $days, $hours, $mins);
	@make_date_marr = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
	@gmt = gmtime(time());
	@lct = localtime(time());
	$days = $lct[3] - $gmt[3];
	$hours = ($days < -1 ? 24 : 1 < $days ? -24 : $days * 24) + $lct[2] - $gmt[2];
	$mins = $hours * 60 + $lct[1] - $gmt[1];
	$timezone = ($mins < 0 ? "-" : "+"); $mins = abs($mins);
	$timezone .= sprintf "%2.2d%2.2d", $mins/60, $mins%60;
}

%messagesfile = ();
%messages = ();
&LoadMessageHashes();  # $messages{$lang}->{$keywore}=$messageStr;

if($config{'qtssAutoStart'} == 1) { #yes
# check if the streaming server is running by trying to connect 
# to it. If the server doesn't respond, look for the name of the 
# streaming server binary in the config file and start it
	if(!($iaddr = inet_aton($config{'qtssIPAddress'}))) { #localhost
		if($debug) { print "No host: $config{'qtssIPAddress'}\n"; }
	}
	$paddr = sockaddr_in($config{'qtssPort'}, $iaddr);  #554
	$proto = getprotobyname('tcp'); #6
	if(!socket(TEST_SOCK, PF_INET, SOCK_STREAM, $proto)) {
    	if($debug) { print "Couldn't create socket to connect to the Streaming Server: $!\n"; 	}
	}
	if(!connect(TEST_SOCK, $paddr)) { #NO
    	if($debug) {
			print "Couldn't connect to the Streaming Server at $config{'qtssIPAddress'} "
			    . " on port $config{'qtssPort'}\n";
			if($^O eq "MSWin32") { print "Please start Darwin Streaming Server from the Service Manager\n";	}
    	}
	    #$prog = $config{'qtssName'};
	}
	close(TEST_SOCK);
}

#Start Play list
# once the config options are read in and the local QTSS is started up
# start playlists that died due to a crash/reboot
my $startplaylists = "";
if (($config{'root'} !~ /\/$/) && ($config{'root'} !~ /\\$/)) {
    if ($^O eq "MSWin32") {#C:/Program Files/Darwin Streaming Server/AdminHtml\startplaylists.pl
		$startplaylists = $config{'root'} . "\\startplaylists.pl";    }  
} else { #NO
    $startplaylists = $config{'root'} . "startplaylists.pl";
}
if ($debug){ print "Running the startplaylists.pl script at $startplaylists\n";}
do $startplaylists;

# Open main socket: 1220
$proto = getprotobyname('tcp');  #6
$baddr = $config{"bind"} ? inet_aton($config{"bind"}) : INADDR_ANY;
$port = $config{"port"};  #1220
$servaddr = sockaddr_in($port, $baddr);
socket(MAIN, PF_INET, SOCK_STREAM, $proto) || die "Failed to open listening socket for Streaming Admin Server : $!\n";
setsockopt(MAIN, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)); #unsigned long, refer to http://www.tutorialspoint.com/perl/perl_pack.htm
bind(MAIN, $servaddr) || die "Failed to start Streaming Admin Server.\n"
								. "Port $config{port} is in use by another process.\n"
								. "The Streaming Admin Server may already be running.\n";  
# Listen to 1220
listen(MAIN, SOMAXCONN) || die "Failed to listen on socket for Streaming Admin Server: $!\n";


# open another listening socket for ssl requests
# only do this if the Net::SSLeay module is available
if ($ssl_available) { #No
	$sslport = $config{"sslport"};
	$servssladdr = sockaddr_in($sslport, $baddr);
	socket(SSLMAIN, PF_INET, SOCK_STREAM, $proto) || die "Failed to open ssl listening socket for Streaming Admin Server : $!\n";
	setsockopt(SSLMAIN, SOL_SOCKET, SO_REUSEADDR, pack("l", 1));  #unsigned long, refer to http://www.tutorialspoint.com/perl/perl_pack.htm
	bind(SSLMAIN, $servssladdr) || die "Failed to start Streaming Admin Server.\n"
									. "SSL Port $config{port} is in use by another process.\n"
									. "The Streaming Admin Server may already be running.\n";  

	# if sslport = 0, then get the port we actually bound to
	# so that we can redirect to the right port later
	if ($sslport == 0) {
		$sslsockaddr = getsockname(SSLMAIN);
		($sslport, $ssladdr) = unpack_sockaddr_in($sslsockaddr);
	}
	
	listen(SSLMAIN, SOMAXCONN) || die "Failed to listen on socket for Streaming Admin Server: $!\n";
}


# write out the PID file
# Not used for NT
if(defined($config{'pidfile'}) && ($config{'pidfile'} ne "")) { $write_pid = 1; }

$SIG{'PIPE'} = 'IGNORE';
@deny = &to_ipaddress(split(/\s+/, $config{"deny"}));
@allow = &to_ipaddress(split(/\s+/, $config{"allow"}));
$p = 0;
while(1) { # wait for a new connection, or a message from a child process
    undef($rmask);
    vec($rmask, fileno(MAIN), 1) = 1;
    if ($ssl_available) {  vec($rmask, fileno(SSLMAIN), 1) = 1; }  # add ssl socket to select mask, only do this if the Net::SSLeay module is available

    local $sel = select($rmask, undef, undef, 10);  #listen to socket 1220
    if ($need_restart) { &restart_streamingadminserver(); }
    next if ($sel <= 0);
	
	#******** socket data arrived **************
    $nonsslrequest = 0; $sslrequest = 0;
    if($ssl_available) {#No
	    if (vec($rmask, fileno(MAIN), 1)) { $nonsslrequest = 1; $sslrequest = 0; } elsif (vec($rmask, fileno(SSLMAIN), 1)) { $nonsslrequest = 0; $sslrequest = 1; }
    } else {
    	 if (vec($rmask, fileno(MAIN), 1)) { $nonsslrequest = 1; } #YES
    	 $sslrequest = 0;	# if ssl request isn't avaiable, sslrequest will always be zero
    }
    
    if ($nonsslrequest || $sslrequest) {#YES, got new connection
		if($nonsslrequest) {#Yes
			$acptaddr = accept(SOCK, MAIN);
		} elsif($sslrequest) {#no
			$acptaddr = accept(SOCK, SSLMAIN);
		}
		if (!$acptaddr) { next; }

		select(SOCK); $| = 1;  #set the currently selected filehandle to always flush buffer after each output operation
		select(STDOUT);

		if($^O eq "MSWin32") {
			if ($sslrequest && $ssl_available) {#NO
				#deleted many lines by andy, # Initialize SSL for this connection
			}
		
		    # Work out the hostname for this web server
		    if (!$config{'host'}) {#YES
				($myport, $myaddr) = unpack_sockaddr_in(getsockname(SOCK));
				$myname = gethostbyaddr($myaddr, AF_INET);
				if ($myname eq "") { $myname = inet_ntoa($myaddr);	}
				$host = $myname;
		    } else {
				$host = $config{'host'};
			}

		    while(&handle_request($acptaddr)) { } #all the work is done here
		    shutdown(SOCK, 1);
	    	close(SOCK);
		} else {
			#delete many lines by andy
		}#if($^O eq "MSWin32")
    }#if ($nonsslrequest || $sslrequest)
}#while

# usage
sub usage {
    printf("Usage: streamingadminserver.pl [-cd] [configfilepath]\n");
    printf("    Command                                           How it works\n");
    printf("    -------                                           ------------\n");
    printf("1. streamingadminserver.pl                           uses default config file\n");
    printf("                                                     if found at $_[0]\n");
    printf("                                                     else uses internal defaults\n");
    printf("2. streamingadminserver.pl -d                        uses default config as above\n");
    printf("                                                     and runs in debug mode\n");
    printf("3. streamingadminserver.pl -c  xyzfilepath           uses config file at 'xyzfilepath'\n");
    printf("4. streamingadminserver.pl -dc  xyzfilepath          like 3. above and runs in debug mode\n");
    printf("5. streamingadminserver.pl -cd  xyzfilepath          like 3. above and runs in debug mode\n");
}

# check_sslconfig(configfilename, defaultvalue, sslavailable)
# reread the config file to check if 
# ssl is on or off and return 0/1
# if file doesn't exist, return the default value
# if openssl isn't available on the OS, then return 0
sub check_sslconfig {
	my $configfilename = $_[0];
	my $sslValue = $_[1];
	my $available = $_[2];
	my $name;
	my $val;
	
	# if openssl isn't available on os, check_sslconfig
	# always returns 0
	if($available == 0) {
	    $sslValue = 0;
	    return $sslValue;
	}
	
	if(open(CONF, $configfilename)) {
		while(<CONF>) {
		    chomp;
	    	if (/^#/ || !/\S/) { 
				next; 
	    	}
	    	/^([^=]+)=(.*)$/;
	    	$name = $1; $val = $2;
	    	$name =~ s/^\s+//g; $name =~ s/\s+$//g;
	    	$val =~ s/^\s+//g; $val =~ s/\s+$//g;
	    	if ($name eq "ssl") {
	    		if ($val == 1) {
	    			$sslValue = 1;
	    		} else {
	    			$sslValue = 0;
	    		}
	    		last;
	    	}
		}
		close(CONF);
	}
	
	return $sslValue;
}

# handle_request(clientaddress)
# Where the real work is done
sub handle_request {
	if ($config{"cacheMessageFiles"} eq "0") {
		&LoadMessageHashes();
	}
    $acptip = inet_ntoa((unpack_sockaddr_in($_[0]))[1]);  #127.0.0.1
    $datestr = &http_date(time());  #Sun, 26 Apr 2015 03:17:49 GMT
    # Read the HTTP request and headers
    ($reqline = &read_line()) =~ s/\r|\n//g;  #<SOCK>
    if (!($reqline =~ /^(GET|POST|HEAD)\s+(.*)\s+HTTP\/1\..$/)) {
		&http_error(400, "Bad Request");
    }
    $method = $1; $request_uri = $page = $2;
    
    $use_ssl = &check_sslconfig($conf, $use_ssl, $ssl_available);
    
    # if request came over non-ssl port but ssl is on, redirect to the ssl request
    if(!$sslrequest && $use_ssl) { &http_redirect(1, $host, $sslport, $request_uri); } #no
    
    # if request came over ssl port but ssl is off, redirect to non-ssl request
    if($sslrequest && !$use_ssl) { &http_redirect(0, $host, $port, $request_uri); } #no
	
#parse http header
    %header = ();
    local $lastheader;
	while(1) {
		($headline = &read_line()) =~ s/\r|\n//g;
		last if ($headline eq "");
		if ($headline =~ /^(\S+):\s+(.*)$/) {
			$header{$lastheader = lc($1)} = $2;
		} elsif ($headline =~ /^\s+(.*)$/) {
			$header{$lastheader} .= $headline;
		} else {
			&http_error(400, "Bad Header $headline");
		}
	}
    if (defined($header{'host'})) {
		if ($header{'host'} =~ /^([^:]+):([0-9]+)$/) { #parse host:port "localhost:1220"
	    	$host = $1; 
	    	$port = $2; 
		} else { $host = $header{'host'}; }
    }
    
# Set defaults language: so that english html can be sent if the accept-language header is not given
    my $langDir = $config{"root"} . "/html_en";  # C:/Program Files/Darwin Streaming Server/AdminHtml/html_en
    my $language = "en";
    
    if (defined($header{'accept-language'})) {  # "en-US,en;q=0.8,zh-CN;q=0.6"
		@langArr =	split /,/ , $header{'accept-language'};
	    if($langArr[0] =~ m/^de/) {
	    	$langDir = $config{"root"} . "/html_de";
	    	$language = "de";
	    } elsif($langArr[0] =~ m/^fr/) {
	    	$langDir = $config{"root"} . "/html_fr";
	    	$language = "fr";
	    } elsif($langArr[0] =~ m/^ja/) {
	    	$langDir = $config{"root"} . "/html_ja";
	    	$language = "ja";
	    } else { 
			$langDir = $config{"root"} . "/html_en"; 
			$language = "en";
		}
    }
    
# parse query string => %in	
    $querystring = '';    
    undef(%in);  #http://www.a.com/s/ref=nb?url=search%3Daps&keywords=book
    if ($page =~ /^([^\?]+)\?(.*)$/) { # There is some query string information
		$page = $1;
		$querystring = $2;
		if ($querystring !~ /=/) {
	    	$queryargs = $querystring;
	    	$queryargs =~ s/\+/ /g;
	    	$queryargs =~ s/%(..)/pack("c",hex($1))/ge; # e modifier is to evaluate pack("c",hex($1)) : refer to http://www.tutorialspoint.com/perl/perl_pack.htm			
	    	$querystring = "";
		} else { # Parse query-string parameters
			local @in = split(/\&/, $querystring);
			foreach $i (@in) {
				local ($k, $v) = split(/=/, $i, 2);
				$k =~ s/\+/ /g; $k =~ s/%(..)/pack("c",hex($1))/ge;
				$v =~ s/\+/ /g; $v =~ s/%(..)/pack("c",hex($1))/ge;
				$in{$k} = $v;
			}
		}
    }

#handle POST data
	$posted_data = undef;
	if ($method eq 'POST' &&
    	$header{'content-type'} eq 'application/x-www-form-urlencoded') {
		# Read in posted query string information
		$clen = $header{"content-length"};
		while(length($posted_data) < $clen) {
			$buf = &read_data($clen - length($posted_data));
			if (!length($buf)) {
				&http_error(500, "Failed to read POST request");
			}
			$posted_data .= $buf;
		}
		local @in = split(/\&/, $posted_data);
		foreach $i (@in) {
			local ($k, $v) = split(/=/, $i, 2);
			$k =~ s/\+/ /g; $k =~ s/%(..)/pack("c",hex($1))/ge; 
			$v =~ s/\+/ /g; $v =~ s/%(..)/pack("c",hex($1))/ge; #       
			$in{$k} = $v;
		}
	}

#handle page url	
    $page =~ s/%00//ge;      # strip NULL characters %00 from the request
    $page =~ s/%(..)/pack("c",hex($1))/ge; # replace %XX sequences in page
  
	# delete multiple dots
	while ($page =~ m/\.{2,}/) {
		$page =~ s/\.{2,}/\./;
	}
	
	# must have a MIME type
	if ($page =~ /\.(.+)$/) {
		if ($mime{$1} eq '') {
			$page = '/';
		}
	} else {
		$page = '/';
	}
	
	#prevent windows ports from being opened
	#aux, con, prn, com*, lpt?, nul
	$superDir = $config{'root'};  #C:/Program Files/Darwin Streaming Server/AdminHtml
	$foundFilename = 0;
	$lastPathComponent = '';
	if ($page =~ m/\/([^\/]+)$/) {
		$lastPathComponent = $1;
	}
	if (opendir(FILEDIR, $superDir)) {   #/AdminHtml
		while (defined($subpath = readdir(FILEDIR))) {
			$foundFilename = 1 if $subpath eq $lastPathComponent;
		}
	}
	if ($foundFilename == 0 && opendir(FILEDIR, "$superDir/images")) { #/AdminHtml/images
		while (defined($subpath = readdir(FILEDIR))) {
			$foundFilename = 1 if $subpath eq $lastPathComponent;
		}
	}
	if ($foundFilename == 0 && opendir(FILEDIR, "$superDir/includes")) { #/AdminHtml/include
		while (defined($subpath = readdir(FILEDIR))) {
			$foundFilename = 1 if $subpath eq $lastPathComponent;
		}
	}
	$page = '/' if $foundFilename == 0;

# check address against access list
    if (@deny && &ip_match($acptip, @deny) ||
		@allow && !&ip_match($acptip, @allow)) {
		&http_error(403, "Access denied for $acptip");
		return 0;
    }
    
    # check address against INADDR_LOOPBACK if we 
    # haven't gone past setup assistant yet
    if (&IsAllowedToSetup($config{'root'}, $acptip) == 0) {
    	&http_error(403, "Access denied for $acptip");
		return 0;
    }

# check for the logout flag file, and if existant deny authentication once
    if ($config{'logout'} && -r $config{'logout'}) {
		&write_data("HTTP/1.0 401 Unauthorized\r\n");
		&write_data("Server: $config{server}\r\n");
		&write_data("Date: $datestr\r\n");
		&write_data("WWW-authenticate: Basic ".
			    "realm=\"$config{realm}\"\r\n");
		&write_data("Content-Type: text/html\r\n");
		&write_keep_alive(0);
		&write_data("\r\n");
		&reset_byte_count();
		&write_data("<html>\n<head>\n<title>Please Login</title>\n</head>\n");
		&write_data("<body>\n<h1>Please Login</h1>\n");
		&write_data("<p>Please login to the server as a new user.</p>\n</body>\n</html>\n");
		&log_request($acptip, undef, $reqline, 401, &byte_count());
		unlink($config{'logout'});
		return 0;
    }

# Check for password if needed
    if (%users) {
		$validated = 0;
		
		# check for SSL authentication
		if ($sslrequest && $verified_client) {
			$peername = Net::SSLeay::X509_NAME_oneline(
					Net::SSLeay::X509_get_subject_name(
						Net::SSLeay::get_peer_certificate(
							$ssl_con)));
			foreach $u (keys %certs) {
				if ($certs{$u} eq $peername) {
					$authuser = $u;
					$validated = 2;
					last;
				}
			}
		}
	
		# Check for normal HTTP authentication
		if (!$validated && $header{authorization} =~ /^basic\s+(\S+)$/i) {
	    	# authorization given..
	    	($authuser, $authpass) = split(/:/, &b64decode($1));
	    	if($^O eq "MSWin32") {
				if ($authuser && ($users{$authuser} eq $authpass)) {
		    		$validated = 1;
				}
	    	} else {
				#delete some lines by andy
	    	}
	    	#print STDERR "checking $authuser $authpass -> $validated\n";
		}
		if (!$validated) {
		    # No password given.. ask
		    &write_data("HTTP/1.0 401 Unauthorized\r\n");
		    &write_data("Server: $config{'server'}\r\n");
		    &write_data("Date: $datestr\r\n");
		    &write_data("WWW-authenticate: Basic ".
				"realm=\"$config{'realm'}\"\r\n");
		    &write_data("Content-Type: text/html\r\n");
		    &write_keep_alive(0);
		    &write_data("\r\n");
		    &reset_byte_count();
		    &write_data("<html>\n<head>\n<title>Unauthorized</title>\n</head>\n");
		    &write_data("<body>\n<h1>Unauthorized</h1>\n");
		    &write_data("<p>A password is required to access this\n");
		    &write_data("web server. Please try again. </p>\n</body>\n</html>\n");
		    &log_request($acptip, undef, $reqline, 401, &byte_count());
	   		return 0;
		}

		# Check per-user IP access control
		if ($deny{$authuser} && &ip_match($acptip, @{$deny{$authuser}}) ||
			    $allow{$authuser} && !&ip_match($acptip, @{$allow{$authuser}})) {
			&http_error(403, "Access denied for $acptip");
			return 0;
		}	
    }
    

    # Figure out what kind of page was requested
    $simple = &simplify_path($page, $bogus);
    if ($bogus) {  &http_error(400, "Invalid path");  }
    $sofar = ""; $full = $config{"root"} . $sofar; #C:/Program Files/Darwin Streaming Server/AdminHtml
    $scriptname = $simple;
    foreach $b (split(/\//, $simple)) { #first time skip
		if ($b ne "") { $sofar .= "/$b"; }
		$full = $config{"root"} . $sofar;
		@st = stat($full);
		if (!@st) {
			$full =  $langDir . $sofar;
			@st = stat($full);
			if(@st) {
				my $redirectUrl = "/html_" . "$language" . $sofar;
				&http_redirect($use_ssl, $host, $config{'port'}, $redirectUrl);
			} else {
				&http_error(404, "File not found"); 
			}
		}
	
		# Check if this is a directory
		if (-d $full) { # It is.. go on parsing
	    	next;
		}
	
		# Check if this is a CGI program
		if (&get_type($full) eq "internal/cgi") {
		    $pathinfo = substr($simple, length($sofar));
		    $pathinfo .= "/" if ($page =~ /\/$/);
	    	$scriptname = $sofar;
	    	last;
		}
    }

    # check filename against denyfile regexp
    local $denyfile = $config{'denyfile'};
    if ($denyfile && $full =~ /$denyfile/) {
		&http_error(403, "Access denied to $page");
		return 0;
    }

# get $idx_full, Reached the end of the path OK.. see what we've got
    if (-d $full) {#C:/dss/AdminHtml
    	# See if the URL ends with a / as it should
		if ($page !~ /\/$/) {
	    	# It doesn't.. redirect
	   		&write_data("HTTP/1.0 302 Moved Temporarily\r\n");
	    	$portstr = ($sslrequest) ? ":$sslport" : ":$port";
	    	&write_data("Date: $datestr\r\n");
	    	&write_data("Server: $config{'server'}\r\n");
	    	$prot = $sslrequest ? "https" : "http";
	    	&write_data("Location: $prot://$host$portstr$page/\r\n");
	    	&write_keep_alive(0);
	    	&write_data("\r\n");
	    	&log_request($acptip, $authuser, $reqline, 302, 0);
	    	return 0;
		}
		# A directory.. check for index files, dss/AdminHtml/parse_xml.cgi
		foreach $idx (split(/\s+/, $config{'index_docs'})) {#index.html parse_xml.cgi index.htm index.cgi
	    	$idxfull = "$full/$idx";  #C:/dss/AdminHtml/parse_xml.cgi
	    	if (-r $idxfull && !(-d $idxfull)) {
				$full = $idxfull;
				$scriptname .= "/" if ($scriptname ne "/");
				last;
		    }
		} #foreach $idx
    }# if (-d $full)

    if (-d $full) { # A directory should NOT be listed. 
		&http_error(404, "File not found");  # Instead a 404 should be returned
		return 0;
    }

# CGI or normal file
    local $rv;
    if (&get_type($full) eq "internal/cgi") {
		# A CGI program to execute
		$envtz = $ENV{"TZ"};
		$envuser = $ENV{"USER"};
		$envpath = $ENV{"PATH"};
		# workaround for windows bug - don't clear out ENV for windows
		# when PLB and MP3B get launched, their ENV vars
		# are not all there which gives rise to Win 10106 error

		$ENV{"HOME"} = $user_homedir;
		$ENV{"SERVER_SOFTWARE"} = $config{"server"};
		$ENV{"SERVER_NAME"} = $host;
		$ENV{"SERVER_ADMIN"} = $config{"email"};
		$ENV{"SERVER_ROOT"} = $config{"root"};
		if($sslrequest) {
			$ENV{"SERVER_PORT"} = $sslport;
    	} else {
    		$ENV{"SERVER_PORT"} = $port;
    	}
        $ENV{"PLAYLISTS_ROOT"} = $config{"plroot"};
        $ENV{"GBROWSE_FLAG"} = $config{"gbrowse"};
		$ENV{"REMOTE_HOST"} = $acptip;
		$ENV{"REMOTE_ADDR"} = $acptip;
		$ENV{"REMOTE_USER"} = $authuser if (defined($authuser));
		$ENV{"SSL_USER"} = $peername if ($validated == 2);
		$ENV{"DOCUMENT_ROOT"} = $config{"root"};
		$ENV{"GATEWAY_INTERFACE"} = "CGI/1.1";
		$ENV{"SERVER_PROTOCOL"} = "HTTP/1.0";
		$ENV{"REQUEST_METHOD"} = $method;
		$ENV{"SCRIPT_NAME"} = $scriptname;
		$ENV{"REQUEST_URI"} = $request_uri;
		$ENV{"PATH_INFO"} = $pathinfo;
		$ENV{"PATH_TRANSLATED"} = "$config{root}/$pathinfo";
		$ENV{"QUERY_STRING"} = $querystring;
		$ENV{"QTSSADMINSERVER_CONFIG"} = $conf;
		$ENV{"QTSSADMINSERVER_QTSSIP"} = $config{"qtssIPAddress"};
		$ENV{"QTSSADMINSERVER_QTSSPORT"} = $config{"qtssPort"};
		$ENV{"QTSSADMINSERVER_QTSSNAME"} = $config{"qtssName"};
		$ENV{"QTSSADMINSERVER_QTSSAUTOSTART"} = $config{"qtssAutoStart"};
		$ENV{"QTSSADMINSERVER_QTSSQTPASSWD"} = $config{"qtssQTPasswd"};
		$ENV{"QTSSADMINSERVER_QTSSPLAYLISTBROADCASTER"} = $config{"qtssPlaylistBroadcaster"};
		$ENV{"QTSSADMINSERVER_QTSSMP3BROADCASTER"} = $config{"qtssMP3Broadcaster"};
		$ENV{"QTSSADMINSERVER_QTSSADMIN"} = $config{"qtssAdmin"};
		$ENV{"QTSSADMINSERVER_HELPURL"} = $config{"helpurl"};
		$ENV{"QTSSADMINSERVER_TEMPFILELOC"} = $config{"tempfileloc"};
		$ENV{"QTSSADMINSERVER_EN_MESSAGEHASH"} = $messages{"en"};
		$ENV{"QTSSADMINSERVER_DE_MESSAGEHASH"} = $messages{"de"};
		$ENV{"QTSSADMINSERVER_JA_MESSAGEHASH"} = $messages{"ja"};
		$ENV{"QTSSADMINSERVER_FR_MESSAGEHASH"} = $messages{"fr"};
		$ENV{"GENREFILE"} = 'genres';
		$ENV{"COOKIES"} = $header{'cookie'};
		$ENV{"COOKIE_EXPIRE_SECONDS"} = $config{"cookieExpireSeconds"};
		$ENV{"LANGDIR"} = $langDir;
		$ENV{"LANGUAGE"} = $language;
		$ENV{"SSL_AVAIL"} = $ssl_available;
		$ENV{"HTTPS"} =  "ON" if ($use_ssl);
		if (defined($header{"content-length"})) {
	    	$ENV{"CONTENT_LENGTH"} = $header{"content-length"};
		}
		if (defined($header{"content-type"})) {
	    	$ENV{"CONTENT_TYPE"} = $header{"content-type"};
		}
		if (defined($header{"user-agent"})) {
			$ENV{"USER_AGENT"} = $header{"user-agent"};
		}
		foreach $h (keys %header) {
		    ($hname = $h) =~ tr/a-z/A-Z/;
		    $hname =~ s/\-/_/g;
		    $ENV{"HTTP_$hname"} = $header{$h};
		}
		$full =~ /^(.*\/)[^\/]+$/; $ENV{"PWD"} = $1;
		foreach $k (keys %config) {
		    if ($k =~ /^env_(\S+)$/) {
				$ENV{$1} = $config{$k};
	    	}
		}
	
		# Check if the CGI can be handled internally
		open(CGI, $full);
		local $first = <CGI>; #!/usr/bin/perl
		close(CGI);
		$perl_cgi = 0;
		if ($^O eq "MSWin32") { #YES
		    if ($first =~ m/^#!(.*)perl$/i) {
				$perl_cgi = 1;
				undef($postinput);
				undef($postpos);
	    	}
		} else {
	    	if ($first =~ m/#!$perl_path(\r|\n)/ && $] >= 5.004) {
				$perl_cgi = 1;
	    	}
		}
		if($perl_cgi == 1) { #YES
	    	# setup environment for eval
	    	chdir($ENV{"PWD"});
	    	@ARGV = split(/\s+/, $queryargs);
	    	$0 = $full; # $0 contains the name of program being run
	    	if ($posted_data) {
				# Already read the post input
				$postinput = $posted_data;
			} elsif ($method eq "POST") {
				$clen = $header{"content-length"};
				while(length($postinput) < $clen) {
		    		$buf = &read_data($clen - length($postinput));
		    		if (!length($buf)) {
						&http_error(500, "Failed to read ".
				    	"POST request");
		    		}
		    		$postinput .= $buf;
				}
	    	}
	    
	    	if ($config{'log'}) { #1
				open(QTSSADMINSERVERLOG, ">>$config{'logfile'}"); #dss/logs/streamingserver.log
				chmod(0600, $config{'logfile'});
	    	}
	    	# set doneheaders = 1 so that the cgi spits out all the headers
	    	$doneheaders = 1;
	    	
	    	$doing_eval = 1;
	    	eval {
				package main;
				tie(*STDOUT, 'streamingadminserver');
				tie(*STDIN, 'streamingadminserver');
				do $streamingadminserver::full;	# run parse_xml.cgi
				die $@ if ($@);
	    	};
	    	$doing_eval = 0;
	    	if ($@) {
				# Error in perl!
				# Uncomment the first line (and comment the second) for debug
				# Error message has security implications.
				&http_error(500, "Perl execution failed", $@);
				#&http_error(500, "Perl execution failed");
	    	} elsif (!$doneheaders) {
				&http_error(500, "Missing Header");
	    	}
	    
	    	if($^O eq "MSWin32") {
				untie(*STDOUT);
				untie(*STDIN);
				$doneheaders = 0;
	    	}
	    	$rv = 0;
		} 
    } else {
    	# if MIME type is text/plain, make sure the file ends in .txt
    	# prevents source code revelation on Windows
    	if ((&get_type($full) eq 'text/plain') && (!(full =~ m/\.txt$/))) {
    		&http_error(404, 'Failed to open file');
    	}
    
		# A file to output
		local @st = stat($full);
		open(FILE, $full) || &http_error(404, "Failed to open file");
	
		&write_data("HTTP/1.0 200 OK\r\n");
		&write_data("Date: $datestr\r\n");
		&write_data("Server: $config{server}\r\n");
		&write_data("Content-Type: ".&get_type($full)."\r\n");
		&write_data("Content-Length: $st[7]\r\n");
		&write_data("Last-Modified: ".&http_date($st[9])."\r\n");
		if ($^O eq "MSWin32") {
		    # Since it is one process handling all connections, we can't keep a connection alive
		    &write_keep_alive(0);
		}

		&write_data("\r\n");
		&reset_byte_count();
		while(read(FILE, $buf, 1024) > 0) {
		    &write_data($buf);
		}
		close(FILE);
		if($^O eq "MSWin32") {  	# can't do keep alive when we're just a single process
	   		$rv = 0;
		}
	}
    # log the request
    &log_request($acptip, $authuser, $reqline,
		 $cgiheader{"location"} ? "302" : "200", &byte_count());
    return $rv;
}

# http_error(code, message, body, [dontexit])
sub http_error {
    close(CGIOUT);
    &write_data("HTTP/1.0 $_[0] $_[1]\r\n");
    &write_data("Server: $config{server}\r\n");
    &write_data("Date: $datestr\r\n");
    &write_data("Content-Type: text/html\r\n");
    &write_keep_alive(0);
    &write_data("\r\n");
    &reset_byte_count();
    &write_data("<html><body>\n");
    &write_data("<h1>Error - $_[1]</h1>\n");
    if ($_[2]) {
		&write_data("<pre>$_[2]</pre>\n");
    }
    &write_data("</body></html>\n");
    &log_request($acptip, $authuser, $reqline, $_[0], &byte_count());
}

# http_redirect(use_ssl, host, port, redirecturl, [dontexit])
sub http_redirect {
    close(CGIOUT);
    &write_data("HTTP/1.0 302 Temporarily Unavailable\r\n");
    &write_data("Server: $config{server}\r\n");
    &write_data("Date: $datestr\r\n");
    my $prot = $_[0] ? "https" : "http";
    my $portStr = ($_[2] == 80 && !$_[0]) ? "" : ($_[2] == 443 && $_[0]) ? "" : ":$_[2]";
    &write_data("Location: $prot://$_[1]$portStr$_[3]\r\n");
    &write_data("Connection: close\r\n");
    &write_keep_alive(0);
    &write_data("\r\n");
    &log_request($acptip, $authuser, $reqline, 302, 0);
}

sub get_type {
    if ($_[0] =~ /\.([A-z0-9]+)$/) {
		$t = $mime{$1};
		if ($t ne "") {
			return $t;
		}
    }
    return "text/plain";
}

# simplify_path(path, bogus)
# Given a path, maybe containing stuff like ".." and "." convert it to a
# clean, absolute form.
sub simplify_path {
    local($dir, @bits, @fixedbits, $b);
    $dir = $_[0];
    $dir =~ s/^\/+//g;
    $dir =~ s/\/+$//g;
    @bits = split(/\/+/, $dir);
    
    if ($#bits == 0) {# the path separator in $dir is not '/' maybe it is '\' (windows)
    	$dir =~ s/^\\+//g;
    	$dir =~ s/\\+$//g;
    	@bits = split(/\\+/, $dir);
    }
     
    @fixedbits = ();
    $_[1] = 0;
    foreach $b (@bits) {
        if ($b eq ".") { 	    # Do nothing..
        } elsif ($b eq "..") { 	# Remove last dir
			if (scalar(@fixedbits) == 0) {
				$_[1] = 1;
				return "/";
			}
			pop(@fixedbits);
		} else { 	# Add dir to list
			push(@fixedbits, $b);
		}
    }
    return "/" . join('/', @fixedbits);
}

# b64decode(string)
# Converts a string from base64 format to normal
sub b64decode {
    local($str) = $_[0];
    local($res);
    $str =~ tr|A-Za-z0-9+=/||cd;
    $str =~ s/=+$//;
    $str =~ tr|A-Za-z0-9+/| -_|;
    while ($str =~ /(.{1,60})/gs) {
        my $len = chr(32 + length($1)*3/4);
        $res .= unpack("u", $len . $1 );
    }
    return $res;
}

# ip_match(ip, [match]+)
# Checks an IP address against a list of IPs, networks and networks/masks
sub ip_match {
    local(@io, @mo, @ms, $i, $j);
    @io = split(/\./, $_[0]);
	local $hn;
	if (!defined($hn = $ip_match_cache{$_[0]})) {
		$hn = gethostbyaddr(inet_aton($_[0]), AF_INET);
		$hn = "" if ((&to_ipaddress($hn))[0] ne $_[0]);
		$ip_match_cache{$_[0]} = $hn;
	}    
    for($i=1; $i<@_; $i++) {
	local $mismatch = 0;
	if ($_[$i] =~ /^(\S+)\/(\S+)$/) {
			# Compare with network/mask
			@mo = split(/\./, $1); @ms = split(/\./, $2);
			for($j=0; $j<4; $j++) {
			if ((int($io[$j]) & int($ms[$j])) != int($mo[$j])) {
				$mismatch = 1;
			}
			}
		} elsif ($_[$i] =~ /^\*(\S+)$/) {
			# Compare with hostname regexp
			$mismatch = 1 if ($hn !~ /$1$/);
		} else {
			# Compare with IP or network
			@mo = split(/\./, $_[$i]);
			while(@mo && !$mo[$#mo]) { pop(@mo); }
			for($j=0; $j<@mo; $j++) {
				if ($mo[$j] != $io[$j]) {
					$mismatch = 1;
				}
			}
		}
		return 1 if (!$mismatch);
    }
    return 0;
}

# restart_streamingadminserver()
# Called when a SIGHUP is received to restart the web server. This is done
# by exec()ing perl with the same command line as was originally used
sub restart_streamingadminserver {
    close(SOCK); close(MAIN); close(SSLMAIN);
    foreach $p (@passin) { close($p); }
    foreach $p (@passout) { close($p); }
    if ($logclearer) { kill('TERM', $logclearer);	}
    exec($perl_path, $streamingadminserver_path, @streamingadminserver_argv);
    die "Failed to restart streamingadminserver with $perl_path $streamingadminserver_path";
}

sub trigger_restart {
    $need_restart = 1;
}

sub to_ipaddress {
    local (@rv, $i);
    foreach $i (@_) {
	if ($i =~ /(\S+)\/(\S+)/ || $i =~ /^\*\S+$/) { push(@rv, $i); } else { push(@rv, join('.', unpack("CCCC", inet_aton($i)))); }
    }
    return @rv;
}

# read_line()
# Reads one line from SOCK or SSL
sub read_line {
	local($idx, $more, $rv);
	if ($sslrequest) {
		while(($idx = index($read_buffer, "\n")) < 0) {
			# need to read more..
			if (!($more = Net::SSLeay::read($ssl_con))) {
				# end of the data
				$rv = $read_buffer;
				undef($read_buffer);
				return $rv;
			}
			$read_buffer .= $more;
		}
		$rv = substr($read_buffer, 0, $idx+1);
		$read_buffer = substr($read_buffer, $idx+1);
		return $rv;
	} else { return <SOCK>; }
}

# read_data(length)
# Reads up to some amount of data from SOCK or the SSL connection
sub read_data {
	if ($sslrequest) {
		local($rv);
		if (length($read_buffer)) {
			$rv = $read_buffer;
			undef($read_buffer);
			return $rv;
		} else {
			return Net::SSLeay::read($ssl_con, $_[0]);
		}
	} else {
		local($buf);
		read(SOCK, $buf, $_[0]) || return undef;
		return $buf;
	}
}

# write_data(data)
# Writes a string to SOCK or the SSL connection
sub write_data {
	if ($sslrequest) {
		Net::SSLeay::write($ssl_con, $_[0]);
	} else {
		syswrite(SOCK, $_[0], length($_[0]));
	}
	$write_data_count += length($_[0]);
}

# reset_byte_count()
sub reset_byte_count { $write_data_count = 0; }

# byte_count()
sub byte_count { return $write_data_count; }

# log_request(address, user, request, code, bytes)
sub log_request
{
    if ($config{'log'}) {
		local(@tm, $dstr, $addr, $user, $ident);
		if ($config{'logident'}) {
			# add support for rfc1413 identity checking here
		} else { $ident = "-"; }
		@tm = localtime(time());
		$dstr = sprintf "%2.2d/%s/%4.4d:%2.2d:%2.2d:%2.2d %s",
		$tm[3], $make_date_marr[$tm[4]], $tm[5]+1900,
		$tm[2], $tm[1], $tm[0], $timezone;
		$addr = $config{'loghost'} ? gethostbyaddr(inet_aton($_[0]), AF_INET)
			: $_[0];
		$user = $_[1] ? $_[1] : "-";
		if (fileno(QTSSADMINSERVERLOG)) {
			seek(QTSSADMINSERVERLOG, 0, 2);
		} else {
			open(QTSSADMINSERVERLOG, ">>$config{'logfile'}");
			chmod(0600, $config{'logfile'});
		}
		print QTSSADMINSERVERLOG "$addr $ident $user [$dstr] \"$_[2]\" $_[3] $_[4]\n";
		close(QTSSADMINSERVERLOG);
    }
}

# read_errors(handle)
# Read and return all input from some filehandle
sub read_errors {
    local($fh, $_, $rv);
    $fh = $_[0];
    while(<$fh>) { $rv .= $_; }
    return $rv;
}

sub write_keep_alive {
    local $mode;
    if (@_) { $mode = $_[0]; } else { $mode = &check_keep_alive(); }
    &write_data("Connection: ".($mode ? "Keep-Alive" : "close")."\r\n");
}

sub check_keep_alive {
    return $header{'connection'} =~ /keep-alive/i;
}


sub reaper {
	local($pid);
	do {
	    $pid = waitpid(-1, WNOHANG);
	} while($pid > 0);
}

sub term_handler {
    if (@childpids) {
		kill('TERM', @childpids);
    }
    exit(1);
}

sub http_date {
    local @tm = gmtime($_[0]);
    return sprintf "%s, %d %s %d %2.2d:%2.2d:%2.2d GMT",
    $weekday[$tm[6]], $tm[3], $month[$tm[4]], $tm[5]+1900,
    $tm[2], $tm[1], $tm[0];
}

sub TIEHANDLE {
    my $i; bless \$i, shift;
}

sub WRITE {
    $r = shift;
    my($buf,$len,$offset) = @_;
    &write_to_sock(substr($buf, $offset, $len));
}

sub PRINT {
    $r = shift;
    $$r++;
    &write_to_sock(@_);
}

sub PRINTF {
    shift;
    my $fmt = shift;
    &write_to_sock(sprintf $fmt, @_);
}

sub READ {
    $r = shift;
    substr($_[0], $_[2], $_[1]) = substr($postinput, $postpos, $_[1]);
    $postpos += $_[1];
}

sub OPEN {
	print STDERR "open() called - should never happen!\n";
}
 
sub READLINE {
    if ($postpos >= length($postinput)) {
		return undef;
    }
    local $idx = index($postinput, "\n", $postpos);
    if ($idx < 0) {
		local $rv = substr($postinput, $postpos);
		$postpos = length($postinput);
		return $rv;
    } else {
		local $rv = substr($postinput, $postpos, $idx-$postpos+1);
		$postpos = $idx+1;
		return $rv;
    }
}
 
sub GETC {
    return $postpos >= length($postinput) ? undef
	: substr($postinput, $postpos++, 1);
}
 
sub CLOSE { }
 
sub DESTROY { }

# write_to_sock(data, ...)
sub write_to_sock {
    foreach $d (@_) {
		if ($doneheaders) {
			&write_data($d);
		} else {
			$headers .= $d;
			while(!$doneheaders && $headers =~ s/^(.*)(\r)?\n//) {
				if ($1 =~ /^(\S+):\s+(.*)$/) {
					$cgiheader{lc($1)} = $2;
				} elsif ($1 !~ /\S/) {
					$doneheaders++;
				} else {
					&http_error(500, "Bad Header");
				}
			}

			if ($doneheaders) {
				if ($cgiheader{"location"}) {
					&write_data(
						"HTTP/1.0 302 Moved Temporarily\r\n");
				} elsif ($cgiheader{"content-type"} eq "") {
					&http_error(500, "Missing Content-Type Header");
				} else {
					&write_data("HTTP/1.0 200 OK\r\n");
					&write_data("Date: $datestr\r\n");
					&write_data("Server: $config{server}\r\n");
					&write_keep_alive(0);
				}
				foreach $h (keys %cgiheader) {
					&write_data("$h: $cgiheader{$h}\r\n");
				}
				&write_data("\r\n");
				&reset_byte_count();
				&write_data($headers);
			}
		}
    }
}

sub verify_client {
	local $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert($_[1]);
	if ($cert) {
		local $errnum = Net::SSLeay::X509_STORE_CTX_get_error($_[1]);
		$verified_client = 1 if (!$errnum);
	}
	return 1;
}

sub pem_passwd_cb {
	return $keypassword;
}

sub BINMODE { }

sub END {
    if ($doing_eval) {
	# A CGI program called exit! This is a horrible hack to 
	# finish up before really exiting
	close(SOCK);
	&log_request($acptip, $authuser, $reqline,
		     $cgiheader{"location"} ? "302" : "200", &byte_count());
    }
}

# urlize
# Convert a string to a form ok for putting in a URL
sub urlize {
  local($tmp, $tmp2, $c);
  $tmp = $_[0];
  $tmp2 = "";
  while(($c = chop($tmp)) ne "") {
	if ($c !~ /[A-z0-9]/) {
		$c = sprintf("%%%2.2X", ord($c));
		}
	$tmp2 = $c . $tmp2;
	}
  return $tmp2;
}

sub LoadMessageHashes {
	# Read the messages file for each language
	# and store in a hash variable
	# moved so separate sub so that message file can be reloaded later
	%messagesfile = ();
	$messagesfile{"en"} = $config{'root'} . "/html_en/" . $config{'messagesfile'}; 
	$messagesfile{"de"} = $config{'root'} . "/html_en/" . $config{'messagesfile'}; 
	$messagesfile{"fr"} = $config{'root'} . "/html_en/" . $config{'messagesfile'}; 
	$messagesfile{"jp"} = $config{'root'} . "/html_en/" . $config{'messagesfile'}; 
	
	%messages = ();
	for $lang (keys %messagesfile) {
		# Create a hash for each message file 
		# The keys are the keywords and the values are the message strings
		$messageHashRef = ();
		open(MESSAGES, $messagesfile{$lang}) or die "Couldn't find the $lang language messages file!";
		while($messageLine = <MESSAGES>) {
			if(($messageLine =~ /^#/) || ($messageLine =~ /^\s+$/)) {
				next;
			}
			if($messageLine =~ /^(\s*?)(\S+)(\s+?)\"(.*)\"(\s*)$/) {
				$keyword = $2;
				$messageStr = $4;
			}
			$messageHashRef->{$keyword} = $messageStr;
		}
		$messages{$lang} = $messageHashRef;
	
		close(MESSAGES);
	 }
}

# IsAllowedToSetup
# checks if the ip address is allowed
# needed to check if the request is coming from a local
# IP if setup assitant hasn't run yet
# input:	config root
# returns	0 => if denied
# 			1 => if allowed
sub IsAllowedToSetup {
	my ($configRoot, $clientIP) = @_;
	
	return 1; # always allowed now

	use Sys::Hostname;
	
	my $host = hostname();
	my $addr = inet_aton($host);
    
    my $setupAssistantPath = $configRoot . "/index.html";
	if (-e $setupAssistantPath) {
		# if the index.html file exists, then the setup assistant
		# hasn't successfully completed yet
		
		if ($clientIP == inet_ntoa(INADDR_LOOPBACK)) {# check if client is using loopback address
			return 1;
		} elsif ($clientIP == inet_ntoa($addr)) {
			return 1;
		}
		return 0;
	}	
	return 1;
}