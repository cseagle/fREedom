fREedom is a primitive attempt to provide an IDA Pro independent means
of extracting disassembly information from executables for use with
binnavi (https://github.com/google/binnavi).

WARNING: This software is in its infancy

Background: binnavi is a graphical "binary navigator" useful for reverse
engineering software. binnavi does not contain its own disassembler, instead
relying upon the capabilities of the commercial disassembler, IDA Pro.
binnavi ships with an IDA plugin that extracts required information from an
existing IDA database into a set of binnavi compatible, Postgres tables. The
amount of work that IDA does on behalf of binnavi is not trivial. There is 
a reason there are no open source competitors to IDA. Eliminating binnavi's
dependency on IDA is not quite as trivial as slapping some glue code on top
of a disassembly framework like Capstone (http://www.capstone-engine.org/)
and calling it a day. This project takes some small steps in that direction.
it is thrown together, not well thought out, and it has a long way to go.

Basic use:  
* Use the provided postgres script to setup the initial postgres database.
* Configure your postgres instance appropriately (pg_hba.conf ...)
* `python fREedom.py --database=my_binnavi --user=someone --pass=itsasecret --dbhost=127.0.0.1 --binary=foo.exe`
* Launch binnavi to browse foo.exe

What's here:   
* binnavi's postgres script to build the required Postgres database
* Python scripts to extract from PE32, PE32+, and ELF binaries containing
x86 or x86_64 code. 

What's not here:  
* A Postgres tutorial (see http://www.postgresql.org/). Among other things,
you'll need psycopg2.
* A Capstone installation tutorial (see http://www.capstone-engine.org/)
* Support for anything other than PE32, PE32+, and ELF
* Support for anything other than x86 and x86_64

Limitations:  
* fREedom's disassembly engine is not as thorough as IDA's, lacking many of
the heuristics that IDA uses to identify code.
* There is currently no support for known data types and library function
signatures. binnavi's type system is complex and not well documented.
Substantial effort will be required to process development header files from
many platforms in order to incorporate this information into fREedom generated
disassemblies.
* Parsers (crude at best) are included for only PE32, PE32+, and ELF.
* Disassembly generators are included for only x86 and x86_64.
* My python skills are not good.
