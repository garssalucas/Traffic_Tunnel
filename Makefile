CC=gcc
CFLAGS=-I. -O2 -Wall
DEPS = tunnel.h

# Regra geral para gerar arquivos .o
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

# Compilar o traffic_tunnel
ttunnel: traffic_tunnel.o tunnel.o
	$(CC) -o traffic_tunnel tunnel.o traffic_tunnel.o $(CFLAGS)

# Compilar o monitor
monitor: monitor.o
	$(CC) -o monitor monitor.o $(CFLAGS)

# Regra all incluindo túnel e monitor
all: ttunnel monitor

# Limpeza
clean:
	rm -f *.o traffic_tunnel monitor