from django import forms


class NameForm(forms.Form):
    purl = forms.CharField(label="url")

    