#!/usr/bin/env python3
'''
Instructions:

import pandas as pd
pop_cols = ['time_stamp', 'country', 'country_iso', 'alpha_2_code']
uri = ('preprocessing_output')
dataframe = pd.read_csv(uri, sep=',',header=0, skipinitialspace=True, usecols=pop_cols)
geographic_patterns(dataframe, output_uri, plot_title)
'''
__author__ = 'Motse Lehata'
__email__ = 'mmlehata@me.com'

# Data structures
import pandas as pd
from collections import OrderedDict
# Web tools
import urllib3
import json
import http
# Plotting
from bokeh.plotting import figure, show, ColumnDataSource, save
from bokeh.io import export_png, output_notebook, output_file
from bokeh.models import HoverTool
# Other
import math
#-----------------------------------------------------------------------------
def get_country_values(dataframe):
    country = list(dataframe['country_iso'].value_counts().index)
    value = list(dataframe['country_iso'].value_counts())
    num = len(value)
    index = [i for i in range(num)]
    countries = [list(combo) for combo in zip(index,country,value)]
    return countries
#-----------------------------------------------------------------------------
def show_map(country_xs, country_ys, country_colours, country_names, country_users, outputname, plot_title):
    print("Plotting values...")
    source = ColumnDataSource(
        data = dict(
            x = country_xs,
            y = country_ys,
            colour = country_colours,
            name = country_names,
            users = country_users
        )
    )
    # print(source)
    #output_notebook #outputfile instead
    output_file(outputname)
    tools = 'pan,wheel_zoom,box_zoom,reset,hover,save'
    p = figure(
        title=plot_title,
        tools=tools,
        plot_width=800
        )
    p.patches('x','y',
         fill_color = 'colour',
         fill_alpha = 0.7,
         line_color='white',
         line_width=0.5,
         source=source)
    hover = p.select(dict(type=HoverTool))
    hover.point_policy = 'follow_mouse'
    hover.tooltips = OrderedDict([
        ('Name','@name'),
        ('Number of Users','@users')
        ])
    save(p)
    #export_png(p, filename=outputname)
#-----------------------------------------------------------------------------
def get_geodata():
    print("Retrieving geo data...")
    url = 'https://raw.githubusercontent.com/datasets/geo-boundaries-world-110m/master/countries.geojson'
    http = urllib3.PoolManager()
    r = http.request('GET',url)
    geodata = json.loads(r.data.decode('utf-8'))
    geodata_features = geodata['features']
    return geodata_features
#-----------------------------------------------------------------------------
def geographic_patterns(dataframe, outputname, plot_title):

    print("Counting requests per country of origin...")
    country_list = get_country_values(dataframe)
    geodata_features = get_geodata()
    country_count = pd.DataFrame(country_list,columns=['id','value','count'])
    print("Generating mercator projection...")
    country_xs = []
    country_ys = []
    country_names = []
    country_users = []
    country_colours = []
    colours = ['#FF9999','#FF7F7F','#FF6666','#FF4C4C','#FF3232',
    '#FF1919','#FF0000','#E50000','#CC0000','#B20000','#990000',
    '#7F0000','#660000']
    for country in geodata_features:
        country_name = country['properties']['name']
        country_iso = country['properties']['iso_a2']
        lam = lambda x:x['value'] == country_iso
        
        geometry_type = country['geometry']['type']
        if geometry_type == 'MultiPolygon':
            for poly_coords in country['geometry']['coordinates']:
                country_names.append(country_name)
                coords = poly_coords[0]
                country_xs.append(list(map(lambda x:x[0], coords)))
                country_ys.append(list(map(lambda x:x[1], coords)))
        else:
            country_names.append(country_name)
            coords = country['geometry']['coordinates'][0]
            country_xs.append(list(map(lambda x:x[0], coords)))
            country_ys.append(list(map(lambda x:x[1], coords)))
            
        loops = len(country['geometry']['coordinates'])
        if country_iso in country_count['value'].values:
            lam = lambda x:x['value'] == country_iso
            users = list(country_count.loc[lam, ('count')])
            country_users = country_users + [users[0] for i in range(loops)]
            colour_index = int(math.log(users[0]))
            colour = [colours[colour_index]]
            country_colours=country_colours + [colour for i in range(loops)]
        else:
            country_users = country_users + [0 for i in range(loops)]
            country_colours = country_colours + [['#808080'] for i in range(loops)]
    
    show_map(country_xs, country_ys, country_colours, country_names, country_users, outputname, plot_title)
#-----------------------------------------------------------------------------
def main():
    print("Read the docstring...")
#-----------------------------------------------------------------------------
if __name__ == '__main__':
    print("geographic_patterns is being run directly")
    main()
else:
    print("geographic_patterns is being imported into another module")