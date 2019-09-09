/* UWoffish.c */
/* Clear text protocol simulator POC for testing purposes
 * Coded by khorben <khorben@uberwall.org>
 * UberWall security team \../. .\../ */



#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))


#define BUFSIZE 65536


/* Array */
/* types */
typedef struct _Array
{
	void ** data;
	unsigned int size;
} Array;

static Array * _array_new(void)
{
	Array * array;

	if((array = malloc(sizeof(Array))) == NULL)
		return NULL;
	array->data = NULL;
	array->size = 0;
	return array;
}

static void _array_delete(Array * array)
{
	if(array->size > 0)
		free(array->data);
	free(array);
}

static unsigned int _array_get_size(Array * array)
{
	return array->size;
}

static int _array_set_size(Array * array, unsigned int size)
{
	void * p;

	if((p = realloc(array->data, sizeof(void*) * size)) == NULL)
		return 1;
	array->data = p;
	array->size = size;
	return 0;
}

static void * _array_get(Array * array, unsigned int pos)
{
	if(pos >= array->size)
		return NULL;
	return array->data[pos];
}

static int _array_append(Array * array, void * data)
{
	if(_array_set_size(array, array->size + 1) != 0)
		return 1;
	array->data[array->size-1] = data;
	return 0;
}


/* HashEntry */
/* types */
typedef struct _HashEntry
{
	char * name;
	void * data;
} HashEntry;

static HashEntry * _hashentry_new(char const * name, void * data)
{
	HashEntry * he;

	if((he = malloc(sizeof(HashEntry))) == NULL)
		return NULL;
	if((he->name = strdup(name)) == NULL)
	{
		free(he);
		return NULL;
	}
	he->data = data;
	return he;
}

static void _hashentry_delete(HashEntry * he)
{
	free(he->name);
	free(he);
}

static void _hashentry_set_data(HashEntry * he, void * data)
{
	he->data = data;
}


/* Hash */
typedef Array Hash;

static Hash * _hash_new(void)
{
	Hash * hash;

	if((hash = _array_new()) == NULL)
		return NULL;
	return hash;
}

static void _hash_delete(Hash * hash)
{
	unsigned int i;
	HashEntry * he;

	if((i = _array_get_size(hash)) != 0)
		for(; i > 0; i--)
			if((he = _array_get(hash, i-1)) != NULL)
				_hashentry_delete(he);
	_array_delete(hash);
}

static void * _hash_get(Hash * hash, char const * name)
{
	unsigned int i;
	HashEntry * he;

	if((i = _array_get_size(hash)) == 0)
		return NULL;
	for(; i > 0; i--)
	{
		if((he = _array_get(hash, i-1)) == NULL)
			return NULL;
		if(strcmp(he->name, name) == 0)
			return he->data;
	}
	return NULL;
}

static int _hash_set(Hash * hash, char const * name, void * data)
{
	unsigned int i;
	HashEntry * he;

	if((i = _array_get_size(hash)) != 0)
		for(; i > 0; i--)
		{
			if((he = _array_get(hash, i-1)) == NULL)
				return 1;
			if(strcmp(he->name, name) == 0)
			{
				/* FIXME memory leak? */
				_hashentry_set_data(he, data);
				return 0;
			}
		}
	if((he = _hashentry_new(name, data)) == NULL)
		return 1;
	if(_array_append(hash, he) == 0)
		return 0;
	_hashentry_delete(he);
	return 1;
}


/* Config */
typedef Hash Config;

static Config * _config_new(void)
{
	Config * config;

	if((config = _hash_new()) == NULL)
		return NULL;
	return config;
}

static void _config_delete(Config * config)
{
	int i;
	HashEntry * hi;
	int j;
	HashEntry * hj;

	for(i = _array_get_size(config); i > 0; i--)
	{
		hi = _array_get(config, i-1);
		for(j = _array_get_size(hi->data); j > 0; j--)
		{
			hj = _array_get(hi->data, j-1);
			free(hj->data);
		}
		_hash_delete(hi->data);
	}
	_hash_delete(config);
}

static char * _config_get(Config * config, char const * section,
		char const * variable)
{
	void * p;

	if((p = _hash_get(config, section)) == NULL)
		return NULL;
	return _hash_get(p, variable);
}

static int _config_set(Config * config, char const * section,
		char const * variable, char * value)
{
	Hash * h;

#ifdef DEBUG
	fprintf(stderr, "[%s] %s=%s\n", section, variable, value);
#endif
	if((h = _hash_get(config, section)) != NULL)
		return _hash_set(h, variable, value);
	if((h = _hash_new()) == NULL)
		return 1;
	if(_hash_set(config, section, h) != 0)
	{
		_hash_delete(h);
		return 1;
	}
	return _hash_set(h, variable, value);
}

static char * _load_section(FILE * fp);
static char * _load_variable(FILE * fp, int c);
static char * _load_value(FILE * fp);
static int _config_load(Config * config, char * filename)
{
	FILE * fp;
	char * section;
	char * variable = NULL;
	int c;
	char * str;
	int ret = 0;

	if((section = strdup("")) == NULL)
		return 1;
	if((fp = fopen(filename, "r")) == NULL)
	{
		free(section);
		return 1;
	}
	while((c = fgetc(fp)) != EOF)
	{
		if(c == '#')
			while((c = fgetc(fp)) != EOF && c != '\n');
		else if(c == '[')
		{
			if((str = _load_section(fp)) == NULL)
				break;
			free(section);
			section = str;
		}
		else if(isprint(c))
		{
			if((str = _load_variable(fp, c)) == NULL)
				break;
			free(variable);
			variable = str;
			if((str = _load_value(fp)) == NULL)
				break;
			_config_set(config, section, variable, str);
		}
		else if(c != '\n')
			break;
	}
	free(section);
	free(variable);
	if(!feof(fp))
	{
		errno = EINVAL;
		ret = 1;
	}
	fclose(fp);
	return ret;
}

static char * _load_section(FILE * fp)
{
	int c;
	char * str = NULL;
	int len = 0;
	char * p;

	while((c = fgetc(fp)) != EOF && c != ']' && isprint(c))
	{
		if((p = realloc(str, sizeof(char) * (len+2))) == NULL)
		{
			free(str);
			return NULL;
		}
		str = p;
		str[len++] = c;
	}
	if(c != ']')
	{
		free(str);
		return NULL;
	}
	if(str == NULL)
		return strdup("");
	str[len] = '\0';
	return str;
}

static char * _load_variable(FILE * fp, int c)
{
	char * str;
	int len = 1;
	char * p;

	if((str = malloc(sizeof(char) * (len+1))) == NULL)
		return NULL;
	str[0] = c;
	while((c = fgetc(fp)) != EOF && c != '=' && isprint(c))
	{
		if((p = realloc(str, sizeof(char) * (len+2))) == NULL)
		{
			free(str);
			return NULL;
		}
		str = p;
		str[len++] = c;
	}
	if(c != '=')
	{
		free(str);
		return NULL;
	}
	str[len] = '\0';
	return str;
}

static char * _load_value(FILE * fp)
{
	int c;
	char * str = NULL;
	int len = 0;
	char * p;

	while((c = fgetc(fp)) != EOF && isprint(c))
	{
		if((p = realloc(str, sizeof(char) * (len+2))) == NULL)
		{
			free(str);
			return NULL;
		}
		str = p;
		str[len++] = c;
	}
	if(c != '\n')
	{
		free(str);
		return NULL;
	}
	if(str == NULL)
		return strdup("");
	str[len] = '\0';
	return str;
}


/* UWoffish */
/* types */
typedef struct _FishClient
{
	int answer;
	int fd;
	char bufr[BUFSIZE];
	unsigned int bufr_cnt;
	char bufw[BUFSIZE];
	unsigned int bufw_cnt;
} FishClient;

typedef struct _FishServer
{
	char * section;
	int fd;
	FishClient * clients;
	int clients_cnt;
} FishServer;

/* functions */
static int _fish_error(char * message, int ret);
static int _fish_server_init(FishServer * server, char * service);
static void _fish_server_destroy(FishServer * server);
static int _fish_do(FishServer servers[], int count, Config * config);
static int _UWoffish(char * file, int servicec, char * servicev[])
{
	Config * config;
	FishServer servers[servicec];
	int i;
	int j;
	int ret = 0;

	if((config = _config_new()) == NULL)
		return _fish_error(file, 2);
	if(_config_load(config, file) != 0)
	{
		_config_delete(config);
		return _fish_error(file, 2);
	}
	for(i = 0; i < servicec; i++)
		if((ret = _fish_server_init(&servers[i], servicev[i])) != 0)
			break;
	if(i == servicec)
		ret = _fish_do(servers, servicec, config) ? 2 : 0;
	for(j = 0; j < i; j++)
		_fish_server_destroy(&servers[j]);
	_config_delete(config);
	return ret;
}

static int _fish_error(char * message, int ret)
{
	fprintf(stderr, "%s", "UWoffish: ");
	perror(message);
	return ret;
}

static char * _init_section(char * service, uint16_t * port);
static int _fish_server_init(FishServer * server, char * service)
{
	struct sockaddr_in sa;

	if((server->section = _init_section(service, &(sa.sin_port))) == NULL)
		return 1;
	if((server->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		free(server->section);
		return _fish_error("socket", 2);
	}
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port = htons(sa.sin_port);
	if(bind(server->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0
			|| listen(server->fd, 5) != 0)
	{
		close(server->fd);
		free(server->section);
		return _fish_error("bind", 2);
	}
	server->clients = NULL;
	server->clients_cnt = 0;
	return 0;
}

static char * _init_section(char * service, uint16_t * port)
{
	char * str;

	/* FIXME try getservbyname() */
	*port = strtol(service, NULL, 10);
	if((str = strdup(service)) == NULL)
		_fish_error("malloc", 0);
	return str;
}

static void _fish_server_destroy(FishServer * server)
{
	if(close(server->fd) != 0)
		_fish_error("close", 0);
	free(server->section);
}

static int _do_fd_set(FishServer servers[], int count, fd_set * rfds,
		fd_set * wfds);
static int _do_accept(FishServer * server, Config * config, fd_set * rfds,
		fd_set * rtmp, fd_set * wfds);
static int _do_read(FishServer * server, Config * config, FishClient * client,
		fd_set * rfds, fd_set * rtmp, fd_set * wfds);
static int _do_write(FishClient * client, fd_set * rfds, fd_set * wfds,
		fd_set * wtmp);
static int _fish_do(FishServer servers[], int count, Config * config)
{
	int fdmax;
	fd_set rfds;
	fd_set rtmp;
	fd_set wfds;
	fd_set wtmp;
	int i;
	int j;
	FishClient * client;
	int fdtmp;

	fdmax = _do_fd_set(servers, count, &rfds, &wfds);
	for(rtmp = rfds, wtmp = wfds;; rtmp = rfds, wtmp = wfds)
	{
		if(select(fdmax+1, &rtmp, &wtmp, NULL, NULL) == -1)
		{
			if(errno != EINTR)
				return _fish_error("select", 1);
			continue;
		}
		fdmax = -1;
		for(i = 0; i < count; i++)
		{
			fdtmp = _do_accept(&servers[i], config, &rfds, &rtmp,
					&wfds);
			fdmax = max(fdmax, fdtmp);
			for(j = 0; j < servers[i].clients_cnt; j++)
			{
				client = &servers[i].clients[j];
				if(client->fd == -1)
					continue;
				fdtmp = _do_read(&servers[i], config,
						client, &rfds, &rtmp, &wfds);
				fdmax = max(fdmax, fdtmp);
				if(client->fd == -1)
					continue;
				fdtmp = _do_write(client, &rfds, &wfds, &wtmp);
				fdmax = max(fdmax, fdtmp);
			}
		}
	}
	return 1;
}

static int _do_fd_set(FishServer servers[], int count, fd_set * rfds,
		fd_set * wfds)
{
	int fdmax = -1;
	int i;

	FD_ZERO(rfds);
	FD_ZERO(wfds);
	for(i = 0; i < count; i++)
	{
		fdmax = max(fdmax, servers[i].fd);
		FD_SET(servers[i].fd, rfds);
	}
	return fdmax;
}

static int _fish_client_init(FishClient * client, Config * config,
		char * section, int fd);
static int _do_accept(FishServer * server, Config * config, fd_set * rfds,
		fd_set * rtmp, fd_set * wfds)
{
	FishClient * p;
	int cnt;
	int fd;

	if(!FD_ISSET(server->fd, rtmp))
		return server->fd;
	cnt = server->clients_cnt;
	/* FIXME try to reuse an existing client slot before */
	if((p = realloc(server->clients, sizeof(FishClient) * (cnt+1)))
			== NULL)
	{
		_fish_error("malloc", 0);
		if((fd = accept(server->fd, NULL, 0)) != -1)
			close(fd);
		return -1;
	}
	server->clients = p;
	server->clients_cnt++;
	if(_fish_client_init(&server->clients[cnt], config, server->section,
				server->fd) != 0)
		return -1;
	if(server->clients[cnt].bufw_cnt > 0)
		FD_SET(server->clients[cnt].fd, wfds);
	else
		FD_SET(server->clients[cnt].fd, rfds);
	return max(server->fd, server->clients[cnt].fd);
}

static int _fish_client_init(FishClient * client, Config * config,
		char * section, int fd)
{
	struct sockaddr_in sa;
	size_t size = sizeof(sa);
	char * banner;

	if((client->fd = accept(fd, (struct sockaddr *)&sa, &size)) == -1)
		return _fish_error("accept", 1);
	fprintf(stderr, "%s%s:%d%s", "UWoffish: New connection from ",
			inet_ntoa(sa.sin_addr), sa.sin_port, "\n");
	client->bufr_cnt = 0;
	client->bufw_cnt = 0;
	client->answer = 0;
	if((banner = _config_get(config, section, "banner")) == NULL)
		return 0;
	size = min(BUFSIZE-1, strlen(banner));
	memcpy(client->bufw, banner, size);
	client->bufw[size] = '\n';
	client->bufw_cnt = size+1;
	return 0;
}

static int _do_read(FishServer * server, Config * config, FishClient * client,
		fd_set * rfds, fd_set * rtmp, fd_set * wfds)
{
	size_t len;
	char str[17];
	char * answer;
	unsigned int i;

	if(!FD_ISSET(client->fd, rtmp))
		return client->bufr_cnt < sizeof(client->bufr) ? client->fd
			: -1;
	if((len = read(client->fd, &client->bufr[client->bufr_cnt],
					BUFSIZE - client->bufr_cnt)) <= 0)
	{
		close(client->fd);
		FD_CLR(client->fd, rfds);
		return (client->fd = -1);
	}
	client->bufr_cnt+=len;
	for(i = 0; i < client->bufr_cnt; i++)
	{
		if(client->bufr[i] != '\r' && client->bufr[i] != '\n')
			continue;
		if(client->bufr[i] == '\r' && i+1 < client->bufr_cnt
			&& client->bufr[i+1] == '\n')
#ifdef DEBUG
			client->bufr[i++] = '\0';
		fprintf(stderr, "%s%s%s", "Received: \"", client->bufr, "\"\n");
#else
			i++;
#endif
		client->bufr_cnt-=(i+1);
		memmove(client->bufr, &client->bufr[i+1], client->bufr_cnt);
		sprintf(str, "answer%d", client->answer+1);
		if((answer = _config_get(config, server->section, str)) == NULL)
			answer = _config_get(config, server->section, "answer");
		else
			client->answer++;
		if(answer == NULL || (len = strlen(answer))+1
				> BUFSIZE-client->bufw_cnt)
		{
			close(client->fd);
			FD_CLR(client->fd, rfds);
			return (client->fd = -1);
		}
		memcpy(&client->bufw[client->bufw_cnt], answer, len);
		client->bufw_cnt+=len;
		client->bufw[client->bufw_cnt] = '\n';
		client->bufw_cnt++;
	}
	client->bufr_cnt = 0;
	if(client->bufw_cnt)
		FD_SET(client->fd, wfds);
	return client->fd;
}

static int _do_write(FishClient * client, fd_set * rfds, fd_set * wfds,
		fd_set * wtmp)
{
	int len;

	if(!FD_ISSET(client->fd, wtmp))
		return client->bufw_cnt > 0 ? client->fd : -1;
	if((len = write(client->fd, client->bufw, client->bufw_cnt)) <= 0)
	{
		close(client->fd);
		FD_CLR(client->fd, wfds);
		FD_SET(client->fd, rfds);
		return (client->fd = -1);
	}
	memmove(client->bufw, &client->bufw[len], client->bufw_cnt-len);
	client->bufw_cnt-=len;
	if(client->bufw_cnt == 0)
	{
		FD_CLR(client->fd, wfds);
		FD_SET(client->fd, rfds);
		return -1;
	}
	return client->fd;
}


/* usage */
static int _usage(void)
{
	fprintf(stderr, "%s", "Usage: UWoffish [-f file] service...\n\
  -f	protocol definitions file to load (default: \"UWoffish.conf\")\n");
	return 1;
}


/* main */
int main(int argc, char * argv[])
{
	int o;
	int ret;
	char * file = "UWoffish.conf";

	while((o = getopt(argc, argv, "f:")) != -1)
		switch(o)
		{
			case 'f':
				file = optarg;
				break;
			default:
				return _usage();
		}
	if(optind == argc)
		return _usage();
	if((ret = _UWoffish(file, argc - optind, &argv[optind])) == 1)
		return _usage();
	return ret == 0 ? 0 : 2;
}
