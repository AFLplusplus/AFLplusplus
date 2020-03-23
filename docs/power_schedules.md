# afl++'s power schedules based on AFLfast

<a href="https://mboehme.github.io/paper/CCS16.pdf"><img src="https://mboehme.github.io/paper/CCS16.png" align="right" width="250"></a>
Power schedules implemented by Marcel Böhme \<marcel.boehme@acm.org\>. 
AFLFast is an extension of AFL which is written and maintained by 
Michal Zalewski \<lcamtuf@google.com\>.

AFLfast has helped in the success of Team Codejitsu at the finals of the DARPA Cyber Grand Challenge where their bot Galactica took **2nd place** in terms of #POVs proven (see red bar at https://www.cybergrandchallenge.com/event#results). AFLFast exposed several previously unreported CVEs that could not be exposed by AFL in 24 hours and otherwise exposed vulnerabilities significantly faster than AFL while generating orders of magnitude more unique crashes. 

Essentially, we observed that most generated inputs exercise the same few "high-frequency" paths and developed strategies to gravitate towards low-frequency paths, to stress significantly more program behavior in the same amount of time. We devised several **search strategies** that decide in which order the seeds should be fuzzed and **power schedules** that smartly regulate the number of inputs generated from a seed (i.e., the time spent fuzzing a seed). We call the number of inputs generated from a seed, the seed's **energy**. 

We find that AFL's exploitation-based constant schedule assigns **too much energy to seeds exercising high-frequency paths** (e.g., paths that reject invalid inputs) and not enough energy to seeds exercising low-frequency paths (e.g., paths that stress interesting behaviors). Technically, we modified the computation of a seed's performance score (`calculate_score`), which seed is marked as favourite (`update_bitmap_score`), and which seed is chosen next from the circular queue (`main`). We implemented the following schedules (in the order of their effectiveness, best first):

| AFL flag | Power Schedule             | 
| ------------- | -------------------------- |
| `-p explore` (default)| ![EXPLORE](http://latex.codecogs.com/gif.latex?p%28i%29%3D%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D) |
| `-p fast` | ![FAST](http://latex.codecogs.com/gif.latex?p(i)=\\min\\left(\\frac{\\alpha(i)}{\\beta}\\cdot\\frac{2^{s(i)}}{f(i)},M\\right))  |
| `-p coe` | ![COE](http://latex.codecogs.com/gif.latex?p%28i%29%3D%5Cbegin%7Bcases%7D%200%20%26%20%5Ctext%7B%20if%20%7D%20f%28i%29%20%3E%20%5Cmu%5C%5C%20%5Cmin%5Cleft%28%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D%5Ccdot%202%5E%7Bs%28i%29%7D%2C%20M%5Cright%29%20%26%20%5Ctext%7B%20otherwise.%7D%20%5Cend%7Bcases%7D) |
| `-p quad` | ![QUAD](http://latex.codecogs.com/gif.latex?p%28i%29%20%3D%20%5Cmin%5Cleft%28%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D%5Ccdot%5Cfrac%7Bs%28i%29%5E2%7D%7Bf%28i%29%7D%2CM%5Cright%29) |
| `-p lin` | ![LIN](http://latex.codecogs.com/gif.latex?p%28i%29%20%3D%20%5Cmin%5Cleft%28%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D%5Ccdot%5Cfrac%7Bs%28i%29%7D%7Bf%28i%29%7D%2CM%5Cright%29) |
| `-p exploit` (AFL) | ![LIN](http://latex.codecogs.com/gif.latex?p%28i%29%20%3D%20%5Calpha%28i%29) |
| `-p mmopt` | Experimental: `explore` with no weighting to runtime and increased weighting on the last 5 queue entries |
| `-p rare` | Experimental: `rare` puts focus on queue entries that hit rare edges |
where *α(i)* is the performance score that AFL uses to compute for the seed input *i*, *β(i)>1* is a constant, *s(i)* is the number of times that seed *i* has been chosen from the queue, *f(i)* is the number of generated inputs that exercise the same path as seed *i*, and *μ* is the average number of generated inputs exercising a path.
  
More details can be found in the paper that was accepted at the [23rd ACM Conference on Computer and Communications Security (CCS'16)](https://www.sigsac.org/ccs/CCS2016/accepted-papers/).

PS: In parallel mode (several instances with shared queue), we suggest to run the master using the exploit schedule (-p exploit) and the slaves with a combination of cut-off-exponential (-p coe), exponential (-p fast; default), and explore (-p explore) schedules. In single mode, the default settings will do. **EDIT:** In parallel mode, AFLFast seems to perform poorly because the path probability estimates are incorrect for the imported seeds. Pull requests to fix this issue by syncing the estimates accross instances are appreciated :)

Copyright 2013, 2014, 2015, 2016 Google Inc. All rights reserved.
Released under terms and conditions of Apache License, Version 2.0.
