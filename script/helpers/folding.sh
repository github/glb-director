#!/bin/bash

begin_fold() {
	echo "%%%FOLD {$*}%%%"
}

end_fold() {
	echo "%%%END FOLD%%%"
}
