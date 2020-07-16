#include <iostream>
#include <cstring>
#include "antlr4-runtime.h"
#include "VisualBasic6Lexer.h"
#include "VisualBasic6Parser.h"
#include "VisualBasic6BaseVisitor.h"
#include "VisualBasic6SecondVisitor.h"

using namespace antlr4;
using namespace std;


extern "C" int parse(char* target,size_t len,char* second,size_t lenS);
extern "C" void fuzz(int index, char** ret, size_t* retlen);

#define MAXSAMPLES 10000
#define MAXTEXT 200

string ret[MAXSAMPLES+2];

bool cmp(const string &x, const string &y){return x<y;}

int parse(char* target,size_t len,char* second,size_t lenS) {
    vector<misc::Interval> intervals;
    intervals.clear();
	vector<string> texts;
    texts.clear();
	int num_of_smaples=0;
	//parse the target
	string targetString;
	try{
		targetString=string(target,len);
		ANTLRInputStream input(targetString);
		//ANTLRInputStream input(target);
		VisualBasic6Lexer lexer(&input);
		CommonTokenStream tokens(&lexer);
		VisualBasic6Parser parser(&tokens);
		TokenStreamRewriter rewriter(&tokens);
		tree::ParseTree* tree = parser.startRule();
		if(parser.getNumberOfSyntaxErrors()>0){
			std::cerr<<"NumberOfSyntaxErrors:"<<parser.getNumberOfSyntaxErrors()<<endl;
			return 0;
		}else{
 			VisualBasic6BaseVisitor *visitor=new VisualBasic6BaseVisitor();
			visitor->visit(tree);

			int interval_size = visitor->intervals.size();
			for(int i=0;i<interval_size;i++){
				if(find(intervals.begin(),intervals.end(),visitor->intervals[i])!=intervals.end()){
				}else if(visitor->intervals[i].a<visitor->intervals[i].b){
					intervals.push_back(visitor->intervals[i]);	
				}
			}
			int texts_size = visitor->texts.size();
			for(int i=0;i<texts_size;i++){
				if(find(texts.begin(),texts.end(),visitor->texts[i])!=texts.end()){
				}else if(visitor->texts[i].length()>MAXTEXT){
				}else{
					texts.push_back(visitor->texts[i]);
            	}
			}
            delete visitor;
			//parse sencond
			string secondString;
			try{
				secondString=string(second,lenS);
				//cout<<targetString<<endl;
				//cout<<secondString<<endl;

				ANTLRInputStream inputS(secondString);
				VisualBasic6Lexer lexerS(&inputS);
				CommonTokenStream tokensS(&lexerS);
				VisualBasic6Parser parserS(&tokensS);
				tree::ParseTree* treeS = parserS.startRule();

				if(parserS.getNumberOfSyntaxErrors()>0){
		 			//std::cerr<<"NumberOfSyntaxErrors S:"<<parserS.getNumberOfSyntaxErrors()<<endl;
				}else{
					VisualBasic6SecondVisitor *visitorS=new VisualBasic6SecondVisitor();
					visitorS->visit(treeS);
					texts_size = visitorS->texts.size();
					for(int i=0;i<texts_size;i++){
						if(find(texts.begin(),texts.end(),visitorS->texts[i])!=texts.end()){
                        }else if(visitorS->texts[i].length()>MAXTEXT){
						}else{
							texts.push_back(visitorS->texts[i]);
						}
					}
                    delete visitorS;
				}

				interval_size = intervals.size();
				sort(texts.begin(),texts.end());
				texts_size = texts.size();

				for(int i=0;i<interval_size;i++){
					for(int j=0;j<texts_size;j++){
						rewriter.replace(intervals[i].a,intervals[i].b,texts[j]);
						ret[num_of_smaples++]=rewriter.getText();
						if(num_of_smaples>=MAXSAMPLES)break;
					}
					if(num_of_smaples>=MAXSAMPLES)break;
				}
			}catch(range_error e){
				//std::cerr<<"range_error"<<second<<endl;
			}
		}
	}catch(range_error e){
		//std::cerr<<"range_error:"<<target<<endl;
	}

	return num_of_smaples;
}

void fuzz(int index, char** result, size_t* retlen){
	*retlen=ret[index].length();
	*result=strdup(ret[index].c_str());
}


int main(){
  	ifstream in;
	char target[100*1024];
	int len=0;
  	in.open("/home/codesafe/test.vbs");
	while(!in.eof()){
		in.read(target,102400);
	}
	len=in.gcount();
	cout<<target<<endl;
	cout<<len<<endl;
  	char second[]="i=0\n";
  	int lenS=sizeof(second);
	cout<<lenS<<endl;
  	int num_of_smaples=parse(target,len,second,lenS);
  	for(int i=0;i<num_of_smaples;i++){
     	char* retbuf=nullptr;
     	size_t retlen=0;
     	fuzz(i,&retbuf,&retlen);
     	cout<<retlen<<retbuf<<endl;
  	}
  	cout<<"num_of_smaples:"<<num_of_smaples<<endl;
}

