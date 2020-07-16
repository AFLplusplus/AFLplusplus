#include <iostream>
#include <cstring>
#include "antlr4-runtime.h"
#include "ECMAScriptLexer.h"
#include "ECMAScriptParser.h"
#include "ECMAScriptBaseVisitor.h"
#include "ECMAScriptSecondVisitor.h"
#include "../../include/config.h"
#include "../../examples/custom_mutators/custom_mutator_helpers.h" 
#include "../../config.h"
#include "../../include/afl-fuzz.h"

using namespace antlr4;
using namespace std;


extern "C" void *afl_custom_init(afl_t *afl, unsigned int seed);

extern "C" void *afl_custom_deinit(afl_t *afl, unsigned int seed);

static int parse(char* target,size_t len,char* second,size_t lenS);
static void fuzz(int index, char** ret, size_t* retlen);


#define MAXSAMPLES 10000
#define MAXTEXT 200

string ret[MAXSAMPLES+2];

/*
todo: abandon entry ce tre sa faca? 2 branches
      common_Fuzz_stuff??
      free mutated buff
	  line 1761???
	  Js  expcetion din fisierele generate din // ------------- v8\CVE-2014-7927.md, de ex f2/queue/id:006803,src:000459+000000,time:70371891,op:tree,pos:0
				 f2/queue/id:006805,src:000459+000001,time:70943662,op:tree,pos:0,+cov



*/

#define DATA_SIZE (100)

static const char *commands[] = {

    "GET",
    "PUT",
    "DEL",

};

typedef struct my_mutator {

  afl_t *afl;

  // any additional data here!
  size_t trim_size_current;
  int    trimmming_steps;
  int    cur_step;

  // Reused buffers:
  BUF_VAR(u8, fuzz);
  BUF_VAR(u8, data);
  BUF_VAR(u8, havoc);
  BUF_VAR(u8, trim);
  BUF_VAR(u8, post_process);

} my_mutator_t;

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
void *afl_custom_init(afl_t *afl, unsigned int seed) {

   
   srand(seed);

   return afl; // afl needs to be returned here, is used later on in el->data!!!

}

extern "C" void *afl_custom_deinit(afl_t *afl, unsigned int seed)
{
	
}

bool cmp(const string &x, const string &y){return x<y;}

extern "C" size_t afl_custom_fuzz(void *data, // afl state
                       uint8_t *buf, size_t buf_size, // input data to be mutated
                       uint8_t **out_buf, // output buffer
                       uint8_t *add_buf, size_t add_buf_size,  // add_buf can be NULL
                       size_t max_size) {

	int fd, i=0, n=0, new_hit_cnt=0, orig_hit_cnt;
	size_t  retlen;					 
	char* retbuf;  
    static s32 splicing_with = -1;        /* Splicing with which test case?   */
	static s32 stage_cur, stage_max;      /* Stage progression     */
	afl_state_t *afl = (afl_state_t * )data;


  afl->stage_name = "tree";
  afl->stage_short = "tree";

  struct queue_entry* target;
  u32 tid;
  u8* new_buf_tree;
/*
retry_external_pick_tree:
  // Pick a random other queue entry for passing to external API 
  do { tid = R(afl->queued_paths); } while (tid == afl->current_entry && afl->queued_paths > 1);

  target = afl->queue;

  while (tid >= 100) { target = target->next_100; tid -= 100; }
  while (tid--) target = target->next;

  //Make sure that the target has a reasonable length.

  while (target && (target->len < 2 || target == afl->queue_cur) && afl->queued_paths > 1) {
    target = target->next;
    splicing_with++;
  }
  if (!target) goto retry_external_pick_tree;

  // Read the additional testcase into a new buffer.
  fd = open(target->fname, O_RDONLY);
  if (fd < 0) PFATAL("Unable to open '%s'", target->fname);
  new_buf_tree = ck_alloc_nozero(target->len);
  ck_read(fd, new_buf_tree, target->len, target->fname);
  close(fd);
  */
  stage_max = parse(buf, buf_size, add_buf, add_buf_size);
  //ck_free(new_buf_tree);
  fuzz(stage_max, out_buf, &retlen);
/*
  orig_hit_cnt =  afl->queued_paths + afl->unique_crashes;
 
  for(stage_cur=0;stage_cur<stage_max;stage_cur++){
     char* retbuf=NULL;
     size_t retlen=0;
     fuzz(stage_cur,&retbuf,&retlen);
     if (retbuf) {
        if(retlen>0){
           if (common_fuzz_stuff(afl, retbuf, retlen)) {
             free(retbuf);
             //goto abandon_entry;
           }
        }
      // Reset retbuf/retlen
      free(retbuf);
      retbuf = NULL;
      retlen = 0;
    }
  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_TREE]  += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_TREE] += stage_max;

*/
 	//ret_val = 0;
  	//goto abandon_entry;

	return retlen;

}



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
		ECMAScriptLexer lexer(&input);
		CommonTokenStream tokens(&lexer);
		ECMAScriptParser parser(&tokens);
		TokenStreamRewriter rewriter(&tokens);
		tree::ParseTree* tree = parser.program();
		if(parser.getNumberOfSyntaxErrors()>0){
			//std::cerr<<"NumberOfSyntaxErrors:"<<parser.getNumberOfSyntaxErrors()<<endl;
			return 0;
		}else{
 			ECMAScriptBaseVisitor *visitor=new ECMAScriptBaseVisitor();
			visitor->visit(tree);

			int interval_size = visitor->intervals.size();
			for(int i=0;i<interval_size;i++){
				if(find(intervals.begin(),intervals.end(),visitor->intervals[i])!=intervals.end()){
				}else if(visitor->intervals[i].a<=visitor->intervals[i].b){
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
				ECMAScriptLexer lexerS(&inputS);
				CommonTokenStream tokensS(&lexerS);
				ECMAScriptParser parserS(&tokensS);
				tree::ParseTree* treeS = parserS.program();

				if(parserS.getNumberOfSyntaxErrors()>0){
		 			//std::cerr<<"NumberOfSyntaxErrors S:"<<parserS.getNumberOfSyntaxErrors()<<endl;
				}else{
					ECMAScriptSecondVisitor *visitorS=new ECMAScriptSecondVisitor();
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
	if(!(*result)){
		printf("failed to alloc result in fuzz(), exit(1);"); exit(1);
	}
}


int main(){
  	ifstream in;
	char target[100*1024];
	int len=0;
  	in.open("/home/b/Superion/tree_mutation/js_parser/test.js");
	while(!in.eof()){
		in.read(target,102400);
	}
	len=in.gcount();
	//cout<<target<<endl;
	//cout<<len<<endl;
	in.close();

	char second[100*1024];
	int lenS=0;
  	in.open("/home/b/Superion/tree_mutation/js_parser/test2.js");
	while(!in.eof()){
		in.read(second,102400);
	}
	lenS=in.gcount();
	//cout<<second<<endl;
	//cout<<lenS<<endl;

  	int num_of_smaples=parse(target,len,second,lenS);
  	for(int i=0;i<num_of_smaples;i++){
     	char* retbuf=nullptr;
     	size_t retlen=0;
     	fuzz(i,&retbuf,&retlen);
     	//cout<<retlen<<retbuf<<endl;
  	}
  	cout<<"num_of_smaples:"<<num_of_smaples<<endl;
}

