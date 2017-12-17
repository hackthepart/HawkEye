from scanner import *


import kivy
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.textinput import TextInput


class MyApp(App):
	def __init__(self):
		super(MyApp, self).__init__()
		self.defaultInterface=getDefaultInterface();
		self.defaultInterfaceMAC=getDefaultInterfaceMAC(self.defaultInterface)

	def attemptDefaultGateway(self,button):
		button.disabled=True
		self.defaultGatewayIP.text=getGatewayIP(False)
		button.disabled=False

	def build(self):
		layout = GridLayout(cols=1)
		layout.add_widget(Label(text='Network Scanner'))
		
		layoutInterface=GridLayout(cols=2)
		layoutInterface.add_widget(Label(text='Default Interface'))
		layoutInterface.add_widget(Label(text=''+self.defaultInterface))

		layoutInterface.add_widget(Label(text='Default Interface MAC Address'))
		layoutInterface.add_widget(Label(text=self.defaultInterfaceMAC))

		layout.add_widget(layoutInterface)

		layoutGatewayIP=GridLayout(cols=3)

		layoutGatewayIP.add_widget(Label(text='Default Gateway IP Address'))
		self.defaultGatewayIP=TextInput(multiline=False,text="",hint_text="Enter Default Gateway here")

		layoutGatewayIP.add_widget(self.defaultGatewayIP)
		
		self.buttonAutogatewayIP=Button(text="Get Default gateway Automatically",on_press=self.attemptDefaultGateway)
		layoutGatewayIP.add_widget(self.buttonAutogatewayIP)
		
		layout.add_widget(layoutGatewayIP)
		return layout

if __name__=='__main__':
	MyApp().run()
