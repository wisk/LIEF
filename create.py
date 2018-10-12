import lief

from lief import Logger
Logger.set_level(lief.LOGGING_LEVEL.DEBUG)

b = lief.ELF.Binary.create()
print(b)

for i in range(3):
    s = lief.ELF.Section(f".foo{i}")
    s.content = [i for x in range(0x1000)]
    b.add(s)

print(b)
b.write("/tmp/out")
