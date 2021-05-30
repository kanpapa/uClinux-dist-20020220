import sys, os, string

# Template used then the program is a GUI program
WINMAINTEMPLATE = """
#include <windows.h>

int WINAPI WinMain(
    HINSTANCE hInstance,      // handle to current instance
    HINSTANCE hPrevInstance,  // handle to previous instance
    LPSTR lpCmdLine,          // pointer to command line
    int nCmdShow              // show state of window
    )
{
    extern int Py_FrozenMain(int, char **);
    PyImport_FrozenModules = _PyImport_FrozenModules;
    return Py_FrozenMain(__argc, __argv);
}
"""

SERVICETEMPLATE = """
extern int PythonService_main(int, char **);

int main( int argc, char **argv)
{
    PyImport_FrozenModules = _PyImport_FrozenModules;
    return PythonService_main(argc, argv);
}
"""

subsystem_details = {
    # -s flag        : (C entry point template), (is it __main__?), (is it a DLL?)
    'console'        : (None,                    1,                 0),
    'windows'        : (WINMAINTEMPLATE,         1,                 0),
    'service'        : (SERVICETEMPLATE,         0,                 0),
    'com_dll'        : ("",                      0,                 1),
}

def get_custom_entry_point(subsystem):
    try:
        return subsystem_details[subsystem][:2]
    except KeyError:
        raise ValueError, "The subsystem %s is not known" % subsystem


def makemakefile(outfp, vars, files, target):
    save = sys.stdout
    try:
        sys.stdout = outfp
        realwork(vars, files, target)
    finally:
        sys.stdout = save

def realwork(vars, moddefns, target):
    version_suffix = `sys.version_info[0]`+`sys.version_info[1]`
    print "# Makefile for Microsoft Visual C++ generated by freeze.py script"
    print
    print 'target = %s' % target
    print 'pythonhome = %s' % vars['prefix']
    print
    print 'DEBUG=0 # Set to 1 to use the _d versions of Python.'
    print '!IF $(DEBUG)'
    print 'debug_suffix=_d'
    print 'c_debug=/Zi /Od /DDEBUG /D_DEBUG'
    print 'l_debug=/DEBUG'
    print 'temp_dir=Build\\Debug'
    print '!ELSE'
    print 'debug_suffix='
    print 'c_debug=/Ox'
    print 'l_debug='
    print 'temp_dir=Build\\Release'
    print '!ENDIF'
    print

    print '# The following line assumes you have built Python using the standard instructions'
    print '# Otherwise fix the following line to point to the library.'
    print 'pythonlib = "$(pythonhome)/pcbuild/python%s$(debug_suffix).lib"' % version_suffix
    print

    # We only ever write one "entry point" symbol - either
    # "main" or "WinMain".  Therefore, there is no need to
    # pass a subsystem switch to the linker as it works it
    # out all by itself.  However, the subsystem _does_ determine
    # the file extension and additional linker flags.
    target_link_flags = ""
    target_ext = ".exe"
    if subsystem_details[vars['subsystem']][2]:
        target_link_flags = "-dll"
        target_ext = ".dll"


    print "# As the target uses Python%s.dll, we must use this compiler option!" % version_suffix
    print "cdl = /MD"
    print
    print "all: $(target)$(debug_suffix)%s" % (target_ext)
    print

    print '$(temp_dir):'
    print '  if not exist $(temp_dir)\. mkdir $(temp_dir)'
    print

    objects = []
    libs = ["shell32.lib", "comdlg32.lib", "wsock32.lib", "user32.lib", "oleaut32.lib"]
    for moddefn in moddefns:
        print "# Module", moddefn.name
        for file in moddefn.sourceFiles:
            base = os.path.basename(file)
            base, ext = os.path.splitext(base)
            objects.append(base + ".obj")
            print '$(temp_dir)\%s.obj: "%s"' % (base, file)
            print "\t@$(CC) -c -nologo /Fo$* $(cdl) $(c_debug) /D BUILD_FREEZE",
            print '"-I$(pythonhome)/Include"  "-I$(pythonhome)/PC" \\'
            print "\t\t$(cflags) $(cdebug) $(cinclude) \\"
            extra = moddefn.GetCompilerOptions()
            if extra:
                print "\t\t%s \\" % (string.join(extra),)
            print '\t\t"%s"' % file
            print

        # Add .lib files this module needs
        for modlib in moddefn.GetLinkerLibs():
            if modlib not in libs:
                libs.append(modlib)

    print "ADDN_LINK_FILES=",
    for addn in vars['addn_link']: print '"%s"' % (addn),
    print ; print

    print "OBJS=",
    for obj in objects: print '"$(temp_dir)\%s"' % (obj),
    print ; print

    print "LIBS=",
    for lib in libs: print '"%s"' % (lib),
    print ; print

    print "$(target)$(debug_suffix)%s: $(temp_dir) $(OBJS)" % (target_ext)
    print "\tlink -out:$(target)$(debug_suffix)%s %s" % (target_ext, target_link_flags),
    print "\t$(OBJS) \\"
    print "\t$(LIBS) \\"
    print "\t$(ADDN_LINK_FILES) \\"
    print "\t$(pythonlib) $(lcustom) $(l_debug)\\"
    print "\t$(resources)"
    print
    print "clean:"
    print "\t-rm -f *.obj"
    print "\t-rm -f $(target).exe"
