#!/bin/bash


case $1 in
    dep | node_modules | node_modules/ )
        yarn
        ;;
    examples/ )
        find examples -name '*.toml' | while read -r line; do
            tomlq . "$line" > "${line/toml/json}"
        done
        ;;
esac

