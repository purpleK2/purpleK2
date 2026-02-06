import kconfiglib

kconf = kconfiglib.Kconfig("Kconfig")
kconf.load_config(".config")

filename = "src/kernel/autoconf.h"
include_guard = "AUTOCONF_H"

kconf.write_autoconf(filename)

with open(filename, "r") as f:
    content = f.read()

with open(filename, "w") as f:
    f.write(f"#ifndef {include_guard}\n#define {include_guard} 1\n\n" + content + f"\n#endif // {include_guard}")

