from django import template

register = template.Library()


@register.filter(name='range')
def _range(_min, args=None):
    _max, _step = None, None
    if args:
        if not isinstance(args, int):
            _max, _step = map(int, args.split(','))
        else:
            _max = args
    args = filter(None, (_min, _max, _step))
    return range(*args)

"""{% load range %}

<p>stop 5
{% for value in 5|range %}
{{ value }}
{% endfor %}
</p>

<p>start 5 stop 10
{% for value in 5|range:10 %}
{{ value }}
{% endfor %}
</p>

<p>start 5 stop 10 step 2
{% for value in 5|range:"10,2" %}
{{ value }}
{% endfor %}
</p>"""