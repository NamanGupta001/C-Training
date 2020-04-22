#include <iostream>


using namespace std;

class linuxTest
{
private:
    /* data */
public:
    void add(int a ,int b);
   
};

void linuxTest::add(int a ,int b)
{
    cout<<"Result is "<< a+b ;    
}

void Test::multiply(int a , int b)
{
    cout<<a*b<<"\n";  
    linuxTest ob;  
    ob.add(4,5);
}

int main()
{
    cout<<"Mast chl rha hai\n";
    Test obj;
    obj.multiply(2,7);
    
}
