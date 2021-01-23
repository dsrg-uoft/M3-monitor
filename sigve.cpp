#include <cassert>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <string>
#include <cstring>
#include <thread>
#include <vector>
#include <mutex>
#include <algorithm>
#include <chrono>

const char* PATHNAME = "/tmp/sigve";

enum struct signo {
	kill = 9,
	sigvf = 63,
	sigve = 64,
};

enum struct memory_level {
	unknown = -1,
	bot,
	low,
	high,
	top,
};

unsigned long realtime() {
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);
	return tp.tv_sec * 1000000000UL + tp.tv_nsec;
}

struct sigv_config {
	unsigned long top;
	unsigned long low_wm_init;
	unsigned long high_wm_init;
	int low_wm_ratio;
	int high_wm_ratio;
	int low_wm_period;
	int high_wm_period;
	int wm_increment_percent;
	int high_wm_pool;
	int expected_shrink;
	int kill_time;
	int poll_time;
};

template <class T>
class ring_buffer {
public:
	ring_buffer(int capacity) : ring(std::unique_ptr<T[]>(new T[capacity + 1])),
		capacity(capacity), tail(0) {}
	void push(T val) {
		ring[tail] = val;
		tail = (tail + 1) % capacity;
	}
	T& operator[] (const int index) {
		return ring[(tail - index - 1 + capacity) % capacity];
	}
	const int capacity;
private:
	std::unique_ptr<T[]> ring;
	int tail;
};

class sigv_ring {
public:
	sigv_ring(int low_wm_period, int high_wm_period) :
		low_wm_period(low_wm_period),
		high_wm_period(high_wm_period),
		history(low_wm_period > high_wm_period ? low_wm_period : high_wm_period) {}
	void push(memory_level level) { history.push(level); }
	void calculate_ratios();
	double low_wm_ratio;
	double high_wm_ratio;
private:
	ring_buffer<memory_level> history;
	int low_wm_period;
	int high_wm_period;
};

void sigv_ring::calculate_ratios() {
	int above_top = 0;
	int below_top = 0;
	int above_high = 0;
	int below_high = 0;
	for (int i = 0; i < history.capacity; i++) {
		memory_level level = history[i];
		switch (level) {
		case memory_level::top:
			if (i < high_wm_period) {
				above_top++;
			}
			if (i < low_wm_period) {
				above_high++;
			}
			break;
		case memory_level::high:
			if (i < high_wm_period) {
				below_top++;
			}
			if (i < low_wm_period) {
				above_high++;
			}
			break;
		default:
			if (i < high_wm_period) {
				below_top++;
			}
			if (i < low_wm_period) {
				below_high++;
			}
			break;
		}
	}
	high_wm_ratio = below_top * 1.0 / above_top;
	low_wm_ratio = below_high * 1.0 / above_high;
	fprintf(stderr, "[trace] below_high %d above_high %d low_wm_ratio %f below_top %d above_top %d high_wm_ratio %f\n", below_high, above_high, low_wm_ratio, below_top, above_top, high_wm_ratio);
}

class proc_info {
public:
	std::string pid;
	unsigned long start_time;
	unsigned long rss; // bytes
	static long page_size; // bytes

	proc_info (const char* pid) : pid(pid) {};

	static bool cmp_start_time(proc_info &p0, proc_info &p1) { return p0.start_time > p1.start_time; }

	static bool cmp_rss(proc_info &p0, proc_info &p1) { return p0.rss > p1.rss; }

	bool update_start_time() {
		start_time = read_stat(22);
		if (start_time > 0) {
			return true;
		} else {
			return false;
		}
	}

	bool update_memory() {
		rss = read_stat(24) * page_size;
		if (rss > 0) {
			return true;
		} else {
			return false;
		}
	}

private:
	unsigned long read_stat(int index);
};

long proc_info::page_size = 0;

unsigned long proc_info::read_stat(int index) {
	assert(index == 22 || index == 24); //start_time or rss

	char path[strlen("/proc/32768/stat") + 1];
	sprintf(path, "/proc/%s/stat", this->pid.c_str());
	FILE* fd = fopen(path, "r");
	if (fd == NULL) {
		fprintf(stderr, "[error] unable to open '%s': %s\n", path, strerror(errno));
		return 0;
	}

	char buf[4096];
	size_t len = fread(buf, sizeof(char), 4096 - 1, fd);
	fclose(fd);
	buf[len] = '\0';

	char* tok = strtok(buf, " ");
	unsigned long value = 0;
	int i = 0;
	while (tok != NULL) {
		i++;
		if (i == index) {
			value = strtoul(tok, NULL, 0);
			fprintf(stderr, "[trace] read_stat got %lu for index %d\n", value, i);
			break;
		}
		tok = strtok(NULL, " ");
	}
	return value;
}

struct shared_vector {
	std::vector<proc_info> vector;
	std::mutex mutex;
};

int path_init() {
	if (access(PATHNAME, R_OK | W_OK | X_OK)) {
		if (mkdir(PATHNAME, S_IRWXU | S_IRWXG | S_IRWXO)) {
			fprintf(stderr, "[error] mkdir /tmp/sigve (%d %s)\n", errno, strerror(errno));
			return -1;
		}
		/*
		 * tmp has umask 022 which prevents other users from using sigve
		 * with that said you must also have CAP_KILL (be root) to send signals to other users
		 */
		if (chmod(PATHNAME, S_IRWXU | S_IRWXG | S_IRWXO)) {
			fprintf(stderr, "[error] chmod 0777 /tmp/sigve (%d %s)\n", errno, strerror(errno));
			return -2;
		}
	}
	return 0;
}

unsigned long query_free_mem() {
	struct sysinfo info;
	sysinfo(&info);
	return info.freeram * info.mem_unit;
}

unsigned long query_meminfo_available() {
	FILE* fd = fopen("/proc/meminfo", "r");
	if (fd == NULL) {
		fprintf(stderr, "[error] unable to open /proc/meminfo: %s\n", strerror(errno));
		return 0;
	}
	char buf[4096];
	size_t len = fread(buf, sizeof(char), 4096 - 1, fd);
	fclose(fd);
	buf[len] = '\0';
	const char* header = "MemAvailable:";
	char* pos = strstr(buf, header);
	if (pos == NULL) {
		fprintf(stderr, "[error] could not find MemAvailable in /proc/meminfo\n");
		return 0;
	}
	unsigned long val = strtoul(pos + strlen(header), NULL, 10);
	fprintf(stderr, "[trace] query_meminfo_available got %lu kB\n", val);
	return val * 1024;
}

int send_kill(std::string &pid, signo sig) {
	pid_t _pid = atoi(pid.c_str());

	fprintf(stderr, "[info] (%lu ns) kill %d pid: %d\n", realtime(), static_cast<int>(sig), _pid);
	if(kill(_pid, static_cast<int>(sig))) {
		fprintf(stderr, "[error] send_kill %d to %d (%d %s)\n", static_cast<int>(sig), _pid, errno, strerror(errno));
		return -1;
	}
	return 0;
}

int epoll_init() {
	int inotifyfd = inotify_init();
	if (inotifyfd == -1) {
		fprintf(stderr, "[error] inotify_init (%d %s)\n", errno, strerror(errno));
		return -1;
	}

	int watchfd = inotify_add_watch(inotifyfd, PATHNAME, IN_CREATE);
	if (watchfd == -1) {
		fprintf(stderr, "[error] inotify_add_watch '%s' (%d %s)\n", PATHNAME, errno, strerror(errno));
		return -1;
	}

	int epollfd = epoll_create1(0);
	if (epollfd == -1) {
		fprintf(stderr, "[error] epoll_create1 (%d %s)\n", errno, strerror(errno));
		return -1;
	}

	struct epoll_event watch_event;
	watch_event.events = EPOLLIN;
	watch_event.data.fd = inotifyfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, inotifyfd, &watch_event) == -1) {
		fprintf(stderr, "[error] epoll_ctl: listen_sock (%d %s)\n", errno, strerror(errno));
		return -1;
	}

	return epollfd;
}

void inotify(struct shared_vector &procs) {
	int epollfd = epoll_init();
	if (epollfd == -1) {
		fprintf(stderr, "[error] epoll_init failed cannot recover\n");
		exit(EXIT_FAILURE);
	}

	while (true) {
		int nfds;
		struct epoll_event events[10];

		nfds = epoll_wait(epollfd, events, 10, -1);
		if (nfds == -1) {
			fprintf(stderr, "[error] epoll_wait (%d %s)\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		for (int i = 0; i < nfds; i++) {
			int len;
			char buf[4096]
				__attribute__ ((aligned(__alignof__(struct inotify_event))));

			len = read(events[i].data.fd, buf, sizeof(buf));
			if (len == -1) {
				fprintf(stderr, "[error] read (%d %s)\n", errno, strerror(errno));
			}

			const struct inotify_event* event;
			for (char* ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
				event = (const struct inotify_event*) ptr;
				if (event->mask & IN_CREATE) {
					fprintf(stderr, "[info] registered pid: %s\n", event->name);
					proc_info proc(event->name);
					proc.update_start_time();
					{
						std::lock_guard<std::mutex> guard(procs.mutex);
						procs.vector.push_back(proc);
					}
				} else if (event->mask & IN_DELETE) {
					//TODO: handle this by deleting pid
					fprintf(stderr, "[info] deleted pid: %s\n", event->name);
				} else {
					fprintf(stderr, "[warn] unknown inotify event mask %u\n", event->mask);
				}
			}
		}
	}
}

void poll_mem(struct shared_vector &procs, sigv_config cfg) {
	struct sysinfo info;
	sysinfo(&info);
	unsigned long total = info.totalram * info.mem_unit;
	unsigned long top_time_start = 0;
	unsigned long low_wm = cfg.low_wm_init;
	unsigned long high_wm = cfg.high_wm_init;
	unsigned long wm_increment = cfg.top * (cfg.wm_increment_percent * 1.0 / 100);
	sigv_ring history(cfg.low_wm_period, cfg.high_wm_period);

	while (true) {
		sysinfo(&info);
		unsigned long free = query_meminfo_available();

		unsigned long low_wm_required = total - low_wm;
		unsigned long high_wm_required = total - high_wm;
		unsigned long top_required = total - cfg.top;
		memory_level level = memory_level::unknown;
		if (free < top_required) {
			level = memory_level::top;
		} else if (free < high_wm_required) {
			level = memory_level::high;
		} else if (free < low_wm_required) {
			level = memory_level::low;
		} else {
			level = memory_level::bot;
		}
		history.push(level);
		fprintf(stderr, "[trace] free %lu, low_wm %lu, high_wm %lu, level %d\n", free, low_wm, high_wm, static_cast<int>(level));
		assert(level != memory_level::unknown);

		if (level < memory_level::top) {
			fprintf(stderr, "[debug] reset top_time_start\n");
			top_time_start = 0;
		}

		if (level >= memory_level::low) {
			{
				std::lock_guard<std::mutex> guard(procs.mutex);
				for (auto it = procs.vector.begin(); it != procs.vector.end();) {
					if (send_kill(it->pid, signo::sigve)) {
						it = procs.vector.erase(it);
					} else {
						it++;
					}
				}
			}

			history.calculate_ratios();
			if (level == memory_level::high && history.high_wm_ratio >= cfg.high_wm_ratio) {
				high_wm = std::min(high_wm + wm_increment, cfg.top);
			}
			if (history.low_wm_ratio >= cfg.low_wm_ratio) {
				low_wm = std::min(low_wm + wm_increment, high_wm);
			}
		}

		if (level >= memory_level::high) {
			// get all processes sorted from newest to oldest
			std::vector<proc_info> procs_time_sorted;
			{
				std::lock_guard<std::mutex> guard(procs.mutex);
				procs_time_sorted = procs.vector;
			}
			std::sort(procs_time_sorted.begin(), procs_time_sorted.end(), proc_info::cmp_start_time);

			// select high wm process pool of newest processes totalling high_wm_pool % of system memory
			std::vector<proc_info> high_wm_proc_pool;
			unsigned long memory = 0;
			unsigned long high_wm_pool_memory = high_wm * (cfg.high_wm_pool * 1.0 / 100);
			unsigned long reclaim_goal = high_wm_required - free;
			unsigned long reclaimable = 0;
			for (proc_info &proc : procs_time_sorted) {
				proc.update_memory();
				fprintf(stderr, "[debug] processes by time %s %lu\n", proc.pid.c_str(), proc.rss);
				high_wm_proc_pool.push_back(proc);
				memory += proc.rss;
				reclaimable += proc.rss * (cfg.expected_shrink * 1.0 / 100);
				if (memory > high_wm_pool_memory && reclaimable > reclaim_goal) {
					break;
				}
			}

			// get subset of list where total expected shrink memory drops free memory below high wm
			std::sort(high_wm_proc_pool.begin(), high_wm_proc_pool.end(), proc_info::cmp_rss);

			// if you're above top signal everyone or else just signal the "bad" processes
			if (level == memory_level::top && high_wm != cfg.top) {
				for (proc_info &proc : procs_time_sorted) {
					send_kill(proc.pid, signo::sigvf);
				}
			} else if (level >= memory_level::high && high_wm != low_wm) {
				reclaimable = 0;
				for (proc_info &proc : high_wm_proc_pool) {
					fprintf(stderr, "[debug] processes by memory %s %lu\n", proc.pid.c_str(), proc.rss);
					send_kill(proc.pid, signo::sigvf);
					reclaimable += proc.rss * (cfg.expected_shrink * 1.0 / 100);
					if (reclaimable > reclaim_goal) {
						break;
					}
				}
			}

			// only start the kill timer if you're above top
			if (level == memory_level::top) {
				unsigned long time = realtime();
				if (top_time_start == 0) {
					top_time_start = time;
				} else if (time - top_time_start > (unsigned long) cfg.kill_time * 1000 * 1000) {
					// check if we are still over high wm and kill as necessary
					unsigned long new_free = query_meminfo_available();
					unsigned long kill_reclaim_goal = top_required - new_free;
					unsigned long reclaimed = 0;
					fprintf(stderr, "[debug] new_free %lu top_required %lu\n", new_free, top_required);
					if (new_free < top_required) {
						for (proc_info &proc : high_wm_proc_pool) {
							send_kill(proc.pid, signo::kill);
							reclaimed += proc.rss;
							if (reclaimed > kill_reclaim_goal) {
								break;
							}
						}
					}
				} else {
					fprintf(stderr, "[debug] time %lu top_time_start %lu\n", time, top_time_start);
				}
			}

			if (history.low_wm_ratio < cfg.low_wm_ratio) {
				if (wm_increment > low_wm) {
					low_wm = 0;
				} else {
					low_wm -= wm_increment;
				}
			}
			if (level == memory_level::top && history.high_wm_ratio < cfg.high_wm_ratio) {
				if (wm_increment > high_wm) {
					high_wm = 0;
				} else {
					high_wm = std::max(high_wm - wm_increment, low_wm);
				}
			}
		}

		fprintf(stderr, "[info] (%lu ns) free %lu, low_wm %lu, high_wm %lu, level %d\n", realtime(), free, low_wm, high_wm, static_cast<int>(level));
		std::this_thread::sleep_for(std::chrono::milliseconds(cfg.poll_time));
	}
}

int main(int argc, char* argv[]) {
	if (argc != 13) {
		fprintf(stderr, "[error] usage: sigve <top> <initial low wm> <inital high wm> <low wm ratio> <high wm ratio> <high wm pool %%> <expected shrink %%> <kill time> <poll time>\n");
		fprintf(stderr, "\ttop of memory: (bytes) maximum amount of memory the monitor will allow to be used\n");
		fprintf(stderr, "\tlow watermark initial value: (bytes) memory used before sending low watermark signal\n");
		fprintf(stderr, "\thigh watermark: (bytes) memory used before sending high watermark signal\n");
		fprintf(stderr, "\tlow watermark ratio: ratio of ticks below high threshold compared to above\n");
		fprintf(stderr, "\thigh watermark ratio: ratio of ticks below top of memory compared to above\n");
		fprintf(stderr, "\tlow watermark period: number of ticks used to calculate low watermark ratio\n");
		fprintf(stderr, "\thigh watermark period: number of ticks used to calculate high watermark ratio\n");
		fprintf(stderr, "\thigh wm pool %%: percent of system memory processes selected for high watermark signal must account for\n");
		fprintf(stderr, "\texpected shrink %%: estimated %% of memory any process will shrink by\n");
		fprintf(stderr, "\tkill time: time in milliseconds before sending high wm pool kill9 after sending high wm pool the high wm signal\n");
		fprintf(stderr, "\tpoll time: time in milliseconds to poll meminfo\n");
		exit(EXIT_FAILURE);
	}

	unsigned long top = strtoul(argv[1], NULL, 0);
	if (top == 0) {
		fprintf(stderr, "[error] invalid top value: %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] top = %lu\n", top);

	unsigned long low_wm_init = strtoul(argv[2], NULL, 0);
	if (low_wm_init == 0) {
		fprintf(stderr, "[error] invalid initial low wm: %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] low wm = %lu\n", low_wm_init);

	unsigned long high_wm_init = strtoul(argv[3], NULL, 0);
	if (high_wm_init == 0) {
		fprintf(stderr, "[error] invalid initial high wm: %s\n", argv[3]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] high wm = %lu\n", high_wm_init);

	int low_wm_ratio = atoi(argv[4]);
	if (low_wm_ratio == 0) {
		fprintf(stderr, "[error] invalid low wm ratio: %s\n", argv[4]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] low wm ratio = %d\n", low_wm_ratio);

	int high_wm_ratio = atoi(argv[5]);
	if (high_wm_ratio == 0) {
		fprintf(stderr, "[error] invalid high wm ratio: %s\n", argv[5]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] high wm ratio = %d\n", high_wm_ratio);

	int low_wm_period = atoi(argv[6]);
	if (low_wm_period == 0) {
		fprintf(stderr, "[error] invalid low wm period: %s\n", argv[6]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] low wm period = %d\n", low_wm_period);

	int high_wm_period = atoi(argv[7]);
	if (high_wm_period == 0) {
		fprintf(stderr, "[error] invalid high wm period: %s\n", argv[7]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] high wm period = %d\n", high_wm_period);

	int wm_increment_percent = atoi(argv[8]);
	if (wm_increment_percent < 0) {
		fprintf(stderr, "[error] invalid wm increment percent: %s\n", argv[8]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] wm increment percent = %d\n", wm_increment_percent);

	int high_wm_pool = atoi(argv[9]);
	if (high_wm_pool == 0) {
		fprintf(stderr, "[error] invalid high wm pool percentage: %s\n", argv[9]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] high wm pool percentage = %d\n", high_wm_pool);

	int expected_shrink = atoi(argv[10]);
	if (expected_shrink == 0) {
		fprintf(stderr, "[error] invalid expected_shrink: %s\n", argv[10]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] expected_shrink = %d\n", expected_shrink);

	int kill_time = atoi(argv[11]);
	if (kill_time == 0) {
		fprintf(stderr, "[error] invalid kill_time: %s\n", argv[11]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] kill_time = %d\n", kill_time);

	int poll_time = atoi(argv[12]);
	if (poll_time == 0) {
		fprintf(stderr, "[error] invalid poll_time: %s\n", argv[12]);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "[trace] poll_time = %d\n", poll_time);

	if (path_init()) {
		fprintf(stderr, "[error] path_init failed cannot recover\n");
		exit(EXIT_FAILURE);
	}

	sigv_config cfg = {
		top,
		low_wm_init,
		high_wm_init,
		low_wm_ratio,
		high_wm_ratio,
		low_wm_period,
		high_wm_period,
		wm_increment_percent,
		high_wm_pool,
		expected_shrink,
		kill_time,
		poll_time,
	};

	proc_info::page_size = sysconf(_SC_PAGESIZE);
	struct shared_vector procs;
	std::thread t0(inotify, std::ref(procs));
	std::thread t1(poll_mem, std::ref(procs), cfg);

	t0.join();
	t1.join();

	fprintf(stderr, "[error] got past thread join?\n");
	exit(EXIT_FAILURE);
}
