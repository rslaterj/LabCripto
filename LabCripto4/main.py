import os
for n,i,p in [("cont_c1","laboratorio_c1","2221"),
              ("cont_c2","laboratorio_c2","2222"),
              ("cont_c3","laboratorio_c3","2223"),
              ("cont_c4","laboratorio_c4","2224")]:
    os.system(f"docker run -d --name {n} -p {p}:22 {i}")
