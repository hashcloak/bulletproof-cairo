# To be run from the root of the project
#!/bin/sh

cairo-compile tests/test_innerproduct2_fork.cairo --output out/svc.json

cairo-run --program=out/svc.json \
    --print_output --layout=all
