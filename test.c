#include<stdio.h>

// ·½·¨ָÕµĸñª£ºint (*ptr)(char *p) ¼´£º·µ»Øµ(ָÕÃ)(²Îý
typedef int (*CallBackFun)(char *p); // Ϊ»ص÷ý¬ÀÐÃÃΪ CallBackFun£¬²Îýr *p

CallBackFun CallBackFuntemp;

int (*CallBackFunOK)(char *p); 

int Afun(char *p) {    // ·½·¨ Afun£¬¸ñûallBackFun µĸñ¬Ò´˿ÉԿ´×Êһ¸öllBackFun
    printf("Afun »ص÷¡³öûn", p);
    return 0;
}

int Cfun(char *p) {    // ·½·¨ Bfun£¬¸ñûallBackFun µĸñ¬Ò´˿ÉԿ´×Êһ¸öllBackFun
    printf("Cfun »ص÷¡:%s, Nice to meet you!\n", p);
    return 0;
}

int call(CallBackFun pCallBack, char *p) { // ִÐ»ص÷ý½һ£ºͨ¹ý½ʽ
    printf("call ֱ½Ӵòöûn", p);

    pCallBack(p);
    CallBackFunOK = pCallBack;
    CallBackFuntemp = pCallBack;	
    return 0;
}

// int call2(char *p, int (*ptr)(char *p)) 
int call2(char *p, int (*ptr)()) { // ִÐ»ص÷ý½¶þ£ºֱ½Ó¨¹ý¸Õ
    printf("==============\n", p); 
    (*ptr)(p); 
}

int call3(char *p, CallBackFun pCallBack){ // ִÐ»ص÷ý½һ£ºͨ¹ý½ʽ
    printf("--------------\n", p);
    pCallBack(p); 
}

int main() {    

    char *p = "hello";
    call(Afun, p);
    call(Cfun, p);
    char *pp = "hello _______________";
    char *lu = "luguanjun";
    CallBackFunOK(pp);	
    CallBackFuntemp(lu);
    call2(p, Afun);
    call2(p, Cfun);

    call3(p, Afun);
    call3(p, Cfun);

    // int i = getchar();
    // printf("Input: %c \n", i);

    return 0;
}

