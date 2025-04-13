#!/bin/bash


case $1 in
    dep | node_modules | node_modules/ )
        yarn
        ;;
esac

