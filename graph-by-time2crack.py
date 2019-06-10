from bokeh.io import show, output_file
from bokeh.models import ColumnDataSource
from bokeh.palettes import viridis
from bokeh.models.mappers import LinearColorMapper
from bokeh.models import Range1d, LinearAxis
from bokeh.plotting import figure,save
import sys
import re

#bits liberally borrowed from bokeh example code

# need:
# pip install bokeh

# takes pot file or other output file, so hash:password or pwdump style uname:uid:foo:hash:password and makes a graph
# as long as

def big_palette(size, palette_func):
    if size < 256:
        return palette_func(size)
    p = palette_func(256)
    out = []
    for i in range(size):
        idx = int(i * 256.0 / size)
        out.append(p[idx])
    return out

output_file(sys.argv[1]+"q.html")

maxh=0
maxlen=0

#static arrays, but most people won't be cracking passwords over 24 chars
freq=[]
pos=[]
tick=0
total=0
maximv=0

#parse our input file ( #cracked as list, total first )
with open(sys.argv[1]) as inf:
    for line in inf:
        mv = line.rstrip()
        imv = int(mv)

        if total==0:
            total=imv
        else:
            if imv>maximv:
                maximv=imv

maxp=round(total / (maximv*10))*10 # max percentage from 10 to 100
if maxp<1:
    maxp=1
sf=100/maxp

#parse our input file ( #cracked as list, total first )
with open(sys.argv[1]) as inf:
    for line in inf:
        mv = line.rstrip()
        imv = int(mv)

        if total==0:
            total=imv
        else:
            freq.append(imv)
            pos.append(tick)
            tick=tick+1

#get an appropriate palette, and reverse the order
cm = big_palette(tick, viridis)
mcm = cm[::-1]

source = ColumnDataSource(data=dict(lengths=pos, counts=freq, color=mcm ))

p = figure(x_range=(0,tick), y_range=(0,total/sf), plot_height=600, title="Passwords by Time To Crack (number on left, percentage on right)", toolbar_location=None, tools="")

p.xaxis.axis_label='Ticks'
p.yaxis.axis_label='Quantity'

p.extra_y_ranges = {"Percentage": Range1d(start=0, end=maxp)}
p.add_layout(LinearAxis(y_range_name="Percentage"), 'right')

p.vbar(x='lengths', top='counts', width=1, color='color', legend=False, source=source)

p.xgrid.grid_line_color = None
p.ygrid.grid_line_color = None

save(p)
