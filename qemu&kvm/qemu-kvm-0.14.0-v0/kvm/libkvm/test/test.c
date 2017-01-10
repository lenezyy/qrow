
#include<stdio.h>
int main(void)
{
   int a=0x0A;
   int b=0,c=0,d=0,e=0;
asm ("movl %4,%%eax;"
   "cpuid;"
   "movl %%eax,%0;"
   "movl %%ebx,%1;"
   "movl %%ecx,%2;"
   "movl %%edx,%3;"
   :"=&r"(b),"=&r"(c),"=&r"(d),"=&r"(e)    /* b is output operand */
   :"r"(a)    /* a is input operand */
   :"%eax");    /* %eax is clobbered register */
printf("\n%0x\n %0x \n%0x \n%0x\n",b,c,d,e);
}

