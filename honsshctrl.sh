#!/usr/bin/env bash


shopt -s -o nounset


#
#   HonSSH management script.
#
#   Date:       2014, March 1
#   Version:    1.2.3
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


declare -rx Script="${0##*/}"
declare honssh_tac="honssh.tac"
declare honssh_log="logs/honssh.log"
declare honssh_pid="honssh.pid"


# ----- We require one argument.
if [ $# != 1 ]
then
    echo 'ERROR: This script requiers one argument'
    echo "USAGE: $Script HELP"
    exit 1
fi


# ----- If the public/private keys are missing, generate them now.
function pki_check()
{
    if [ ! -e id_rsa ]
    then
        echo "WARNING: Unable to find id_rsa, generating it now..."
        ckeygen -t rsa -f id_rsa
    fi
}

# ----- Start HonSSH
function start_honssh()
{
    if [ ! -e $honssh_pid ]
    then
        echo "Starting honssh in background..."
        twistd -y $honssh_tac -l $honssh_log --pidfile $honssh_pid
    else
        echo "ERROR: There appears to be a PID file already, HonSSH might be running"
        exit 1
    fi
}


# ----- Stop HonSSH
function stop_honssh()
{
    if [ -e $honssh_pid ]
    then
        honey_pid="$(cat $honssh_pid)"
        echo "Attempting to stop HonSSH ($honey_pid)..."
        kill -15 $honey_pid &>/dev/null
        if [ $? != 0 ]
        then
            echo "ERROR: Unable to stop HonSSH ($honey_pid)"        
            exit 1
        else
            echo "OK: HonSSH has been stopped"
        fi
    else
        echo "ERROR: No PID file was found, HonSSH might not be running."
        exit 1
    fi
}


# ----- Help text
function help_honssh()
{
cat << _EOF_

    USAGE: $Script [ARGUMENT]

    $Script      START       Start HonSSH
    $Script      STOP        Stop HonSSH
    $Script      RESTART     Restart HonSSH
    $Script      HELP        Show this help

_EOF_
}


# ----- Check for known arguments, let the user know if they missed anything
if [ $1 = 'START' ]
then
    pki_check
    start_honssh
fi


if [ $1 = 'STOP' ]
then
    stop_honssh
fi


if [ $1 = 'RESTART' ]
then
    stop_honssh
    sleep 0.5
    pki_check
    start_honssh
fi


if [ $1 = 'HELP' ]
then
    help_honssh
fi


if [[ $1 != 'START' && $1 != 'STOP' && $1 != 'HELP' && $1 != 'RESTART' ]]
then
    help_honssh
fi


exit 0
