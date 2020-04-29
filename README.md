# VxHunter

The `vxhunter` directory contains two Ghidra scripts for VxWorks analysis:

    1. `vxworks_symtab.py`: Tries to parse the VxWorks symbol table and add the symbols.
    2. `vxworks_analysis.py`: Inspect parameters for certain VxWorks functions to try and find hardcoded credentials and available services.

If running headless, pass both a script name (to prefix output) and a VxWorks version (5 or 6) as arguments to either script.

Note that `vxworks_symtab` should be run before analysis, and if successful, analysis does not need to be run afterwards. If the script fails to find a symbol table, it will call Ghidra's automatic analysis.

## Testing

There are currently no unit tests, but there are some tests to make sure that any changes made preserve analysis output on some pre-analyzed binaries. Therefore, unless you wanna add tests for it, don't modify the symbol table logic significantly.

To run the analysis tests, first create and activate the virtual environment. To do so, run `./scripts/setup_venv.sh` and the `source venv/bin/activate`.

Then run `./scripts/run_tests.sh`. This will download a large zipped Ghidra project from s3 into a temporary directory. Therefore, it is recommended that you download this zip once and export the environment variable `VX_ZIP_DIR` to it's parent directory.

This way the ~100Mb zip file doesn't need to be downloaded every time the tests are run.
