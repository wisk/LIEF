import lief

b = lief.ELF.Binary.create()
print(b)

b.write("/tmp/out")
