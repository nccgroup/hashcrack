from bokeh.io import show, output_file
from bokeh.models import ColumnDataSource
from bokeh.palettes import plasma
from bokeh.models.mappers import LinearColorMapper
from bokeh.plotting import figure
import sys
import re

#bits liberally borrowed from bokeh example code 

# need:
# pip install bokeh

# takes pot file or other output file, so hash:password or pwdump style uname:uid:foo:hash:password and makes a graph
# as long as 

output_file(sys.argv[1]+".html")

maxh=0
maxlen=0

#static arrays, but most people won't be cracking passwords over 24 chars
freq=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
pos=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23]

#first parse our pot file, or --show output
with open(sys.argv[1]) as inf:
    for line in inf:
        pw = line.split(':')[-1]
        pw = pw.rstrip()

        #convert any HEX strings
        m = re.search('\$HEX\[(.+)\]',pw)
        if m is not None:
            pw=m.group(1).decode("hex")

        pwlen = len(pw)
        
        try:
            freq[pwlen]=freq[pwlen]+1
            
            if maxh<freq[pwlen]:
                maxh=freq[pwlen]

            if maxlen<pwlen:
                maxlen=pwlen
                
        except:
            #don't plot outliers
            az=0
            #print "Discarding outlier " + pw


#get an appropriate palette, and reverse the order 
cm = plasma(maxlen)
mcm = cm[::-1]

source = ColumnDataSource(data=dict(lengths=pos, counts=freq, color=mcm ))

p = figure(x_range=(0,len(freq)), y_range=(0,maxh), plot_height=600, title="Passwords by Length", toolbar_location=None, tools="")

p.xaxis.axis_label='Length'
p.yaxis.axis_label='Count'

p.vbar(x='lengths', top='counts', width=1, color='color', legend=False, source=source)

p.xgrid.grid_line_color = None
p.ygrid.grid_line_color = None

show(p)

#/opt/python2.7.14/bin/python2.7 graph-by-length.py /var/www/jobs/9a51ca938afe9e12c7839c958c1acaab10379edc/cracked-hashes.txt.html
