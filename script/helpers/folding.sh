#!/bin/bash

begin_fold() {
    echo "::group::$*"
}

end_fold() {
    echo "::endgroup::"
}