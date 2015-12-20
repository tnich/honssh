#!/usr/bin/env bash
#
#   HonSSH management script.
#
#   Date:       2014, March 1
#   Version:    1.2.5-1-DEV
#
#   Copyright (c) 2014, Are Hansen - Honeypot Development.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without modification, are
#   permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
#   SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
#   THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#   --------------------------------------------------------------
#
#   - 1.2.3:
#   Enclosed lines 56 - 60 in the pki_check function.
#   This will prevent the keys to be generated if the user passes the HELP argument.
#   The pki_check function should now only be executed prior to calling the start_honssh.
#
#   - 1.2.4:
#   Changed the behaviour of ckeygen to set empty password by default.
#   All output will be logged to syslog and stdout.
#   Log entries will be written according to syslog severities.
#   Script arguments set to lowercase.
#   Replaced the old n' dirty if statements with a case statement.
#
#   - 1.2.5
#   Declared full paths.
#   Added argument to clean up stale pid file.
#   Check executing user permissions.
#
set -e


declare -rx Script="${0##*/}"
declare honssh_tac="honssh.tac"
declare id_rsa="id_rsa"
declare id_dsa="id_dsa"
declare honssh_log="logs/honssh.log"
declare daily_log="logs/$(date +"%Y%m%d")"
declare dl_log="logs/downloads.log"
declare honssh_pid="honssh.pid"
declare proddate="2014, March 1"
declare author="Are Hansen"
declare version="1.2.5-1"


function cleanup_honssh()
{
    check_uid

    if [ -e "$honssh_pid" ]
    then
        logger -p warn "$Script[$$]: Forcibly removing $honssh_pid"
        echo "$Script[$$]: Forcibly removing $honssh_pid"
        sleep 2.5
        rm "$honssh_pid"
        logger -p warn "$Script[$$]: $honssh_pid has been removed."
        echo "$Script[$$]: $honssh_pid has been removed."
    else
        logger -p warn "$Script[$$]: $honssh_pid was not found, unable to remove unexisting files"
        echo "$Script[$$]: $honssh_pid was not found, unable to remove unexisting files"
        exit 1
    fi
}


function start_honssh()
{
    check_uid

    if [ ! -e "$honssh_pid" ]
    then
        logger -p info "$Script[$$]: Starting honssh in background..."
        echo "$Script[$$]: Starting honssh in background..."
        twistd -y "$honssh_tac" -l "$honssh_log" --pidfile "$honssh_pid"
        tail_log "$honssh_log"
    else
        logger -p err "$Script[$$]: ERROR: There appears to be a pid file already, HonSSH might be running."
        echo "$Script[$$]: ERROR: There appears to be a pid file already, HonSSH might be running."
        echo "$Script[$$]: Use \"$Script clean\" if you beleive HonSSH to be stopped with a stale pid file."
        exit 1
    fi
}


function stop_honssh()
{
    check_uid

    if [ -e "$honssh_pid" ]
    then
        honey_pid="$(cat $honssh_pid)"
        logger -p info "$Script[$$]: Attempting to stop HonSSH ($honey_pid)..."
        echo "$Script[$$]: Attempting to stop HonSSH ($honey_pid)..."
        kill -15 "$honey_pid" &>/dev/null
        if [ "$?" != "0" ]
        then
            logger -p err "$Script[$$]: ERROR: Unable to stop HonSSH ($honey_pid)"
            echo "$Script[$$]: ERROR: Unable to stop HonSSH ($honey_pid)"        
            exit 1
        else
            logger -p info "$Script[$$]: HonSSH has been stopped"
            echo "$Script[$$]: HonSSH has been stopped"
        fi
    else
        logger -p err "$Script[$$]: ERROR: No pid file was found, HonSSH might not be running."
        echo "$Script[$$]: ERROR: No pid file was found, HonSSH might not be running."
        exit 1
    fi
}


function pki_check()
{
    check_uid

    if [ ! -e "$id_rsa" ]
    then
        logger -p warn "$Script[$$]: WARNING: Unable to find $id_rsa, generating it now..."
        echo "$Script[$$]: WARNING: Unable to find $id_rsa, generating it now..."
        ckeygen --no-passphrase -t rsa -f "$id_rsa"
    fi
    if [ ! -e "$id_dsa" ]
    then
        logger -p warn "$Script[$$]: WARNING: Unable to find $id_dsa, generating it now..."
        echo "$Script[$$]: WARNING: Unable to find $id_dsa, generating it now..."
        ckeygen --no-passphrase -t dsa -f "$id_dsa"
    fi
}


function check_uid()
{
    if [ "$(id -u)" != "0" ]
    then
        logger -p err "$Script[$$]: You must execute $Script as root!"
        echo "$Script[$$]: You must execute $Script as root!"
        exit 1
    fi
}


function tail_log()
{
    if [ ! -e "$1" ]
    then
        echo "$Script[$$]: Unable to locate $1"
        exit 1
    else
        tail -f -n50 "$1"
    fi
}


function help_honssh()
{
echo "
    $Script - v$version - $proddate - $author

    $Script clean
    - Will attempt to forcibly remove a stale pid file.

    $Script help
    - Shows this help.

    $Script start
    - Starts HonSSH and begins to tail the application log.

    $Script stop
    - Stops HonSSH

    $Script restart
    - Restarts HonSSH

    $Script tail app
    - Begin to tail the application log.

    $Script tail daily
    - Begin to tail the daily log.

    $Script tail dl
    - Begin to tail the download log.
"
}


case "$1" in
    clean)
        cleanup_honssh
        ;;
    help)
        help_honssh
        ;;
    start)
        pki_check
        start_honssh
        ;;
    stop)
        stop_honssh
        ;;
    restart)
        stop_honssh
        sleep 0.5
        pki_check
        start_honssh
        ;;
    tail)
        case "$2" in
            app)
                tail_log "$honssh_log"
                ;;
            daily)
                tail_log "$daily_log"
                ;;
            dl)
                tail_log "$dl_log"
                ;;
            *)
                echo "Usage: $Script tail {app|daily|dl}"
                exit 1
                ;;
        esac
        ;;
    *)
        echo "Usage: $Script {clean|help|restart|start|stop|tail}"
        exit 1
        ;;
esac


exit 0
