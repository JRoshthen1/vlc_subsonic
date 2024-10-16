#!/bin/bash
rsync -av $PWD/extensions/* $HOME/.local/share/vlc/lua/extensions/ && \
#rm -f $HOME/.config/vlc/vlc_subsonic.conf && \
#vlc
