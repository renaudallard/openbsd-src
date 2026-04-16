#ifdef FOO
int foo = 1;
#else
int foo = 0;
#endif

#if defined(BAR) && !defined(BAZ)
void bar(void) {}
#elif defined(BAZ)
void baz(void) {}
#endif
