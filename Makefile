all: parser

parser: compile.sh
	sh compile.sh
	touch compile.sh
