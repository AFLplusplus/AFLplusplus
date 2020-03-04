#include <signal.h> /* sigemptyset(), sigaction(), kill(), SIGUSR1 */
#include <stdlib.h> /* exit() */
#include <unistd.h> /* getpid() */
#include <errno.h> /* errno */
#include <stdio.h> /* fprintf() */

static void mysig_handler(int sig)
{
	exit(2);
}

int main()
{
	/* setup sig handler */
	struct sigaction sa;
       	sa.sa_handler = mysig_handler;
	sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;	
	if (sigaction(SIGCHLD, &sa, NULL)) {
		fprintf(stderr, "could not set signal handler %d, aborted\n", errno);
		exit(1);
	}
	kill(getpid(), SIGCHLD);
	return 0;
}
