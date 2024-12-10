//2
import QtQuick 2.12
import QtQuick.Window 2.12
import QtQuick.Controls 2.12
import "pbkdf2.js" as Hash


Item {
    property var user: userPanel.username
    property var password: passwordField.text
    property var session: sessionPanel.session
    property var inputHeight: Screen.height * config.LoginScale * 0.25
    property var inputWidth: Screen.width * config.LoginScale
	property var users: []
	property var credentialsLoaded: false
    property var iterations: 10000
    property var dkLen: 256

    function bytestringToArray(bytestring) {
    var arr = new Array(bytestring.length);
    for (i = 0; i < bytestring.length; i++) {
        arr[i] = bytestring[i].charCodeAt(0);
    }
    return arr;
    }
	
	function loadCredentials(callback) {
	    users = [];
				
    	var file = Qt.resolvedUrl("credentials.txt");

    	var xhr = new XMLHttpRequest();
    	xhr.onreadystatechange = function() {
        	if (xhr.readyState === XMLHttpRequest.DONE) {
            	if (xhr.status === 200) {
                	var fileContent = xhr.responseText.split("\n");

                	for (var i = 0; i < fileContent.length; i++) {
                    	var credentials = fileContent[i].split(":");
                    	if (credentials.length === 3) {
                        	users.push({ "username": credentials[0], "salt": bytestringToArray(atob(credentials[1])), "hash": bytestringToArray(atob(credentials[2])) });
                    	}
                	}
					credentialsLoaded = true;
					callback();
            	} else {
                	console.error("Failed to load credentials file: " + file + ", status: " + xhr.status);
            	}
        	}
    	};

    	xhr.open("GET", file);
    	xhr.send();
	}

	function checkCredentials(username, password) {
    for (var i = 0; i < users.length; ++i) {
        hash = Hash.PBKDF2_HMAC_SHA256(password, users[i].salt, iterations, dkLen);
        if (users[i].hash === hash) {
            console.log("Credentials are valid for user: " + username);
            return true; // Credentials are valid
        }
    }
    console.log("Invalid credentials for user: " + username);
    return false;
	}
	
	function checkAndLogin() {
    if (credentialsLoaded && checkCredentials(user, password)) {
        root.state = "door";
        videoPlayer2.play();
        videoPlayer2.onStopped.connect(function () {
            videoPlayer3.play();
            videoPlayer3.onStopped.connect(function () {
                sddm.login(user, password, session);
            });
        });
    } else {
        sddm.login(user, password, session);
        passwordField.text = "";
    }
}
	


    Column {
        spacing: 8
        opacity: 0


        anchors {
            bottom: parent.bottom
            left: parent.left
			bottomMargin: 65
            leftMargin: 19
        }

        PowerPanel {
            id: powerPanel
        }
    }
    
        Column {
        spacing: 8
        opacity: 1


        anchors {
            top: parent.top
            right: parent.right
			topMargin: 450
            rightMargin: 19
        }

        DateTimePanel {
            id: dateTimePanel
        }
    }

    Column {
        spacing: 8
        opacity: 1
        anchors {
            top: parent.top
            left: parent.left
			topMargin: 450
            leftMargin: 19
        }

        PlayerPanel {
            id: playerPanel
        }
    }    

    Column {
        spacing: 8
		opacity: 0

        anchors {
            bottom: parent.bottom
            right: parent.right
			bottomMargin: 65
			rightMargin: 19
        }

        SessionPanel {
            id: sessionPanel
        }
    }	


    Column {
        spacing: 10
        width: inputWidth + 10
        anchors.centerIn: parent
        visible: root.state === "login"

	

    
        UserPanel {
            id: userPanel
            anchors.right: parent.right - 20
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: parent.left
        }

        PasswordPanel {
            id: passwordField
			opacity:1

            height: inputHeight -5
            width: parent.width + 20
			anchors.top: parent.top
			anchors.topMargin: 130
			anchors.right: parent.right
			anchors.rightMargin: -12

            onAccepted: loginButton.clicked()
        }

        Button {
            id: loginButton
			opacity:1
            
            height: inputHeight -5
            width: parent.width + 20
			anchors.right: parent.right
			anchors.rightMargin: -10
			anchors.top: parent.top
			anchors.topMargin: 245
			

            enabled: user != "" && password != "" ? true : false
            hoverEnabled: true
            text: "Login!!"

            contentItem: Text {
                id: buttonText

                renderType: Text.NativeRendering
                font.pointSize: config.GeneralFontSize
                font.bold: true
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter

                color: config.LoginButtonTextColor
                opacity: 0.5
                text: config.LoginButtonText
            }
        
            background: Rectangle {
                id: buttonBackground
                color: config.LoginButtonBgColor
                opacity: 0.5
                radius: config.CornerRadius
            }

            states: [
                State {
                    name: "pressed"
                    when: loginButton.down
                    PropertyChanges {
                        target: buttonBackground
                        color: Qt.darker(config.LoginButtonBgColor, 1.4)
                        opacity: 1
                    }
                    PropertyChanges {
                        target: buttonText
                        opacity: 1
                    }
                },
                State {
                    name: "hovered"
                    when: loginButton.hovered
                    PropertyChanges {
                        target: buttonBackground
                        color: Qt.darker(config.LoginButtonBgColor, 1.2)
                        opacity: 1
                    }
                    PropertyChanges {
                        target: buttonText
                        opacity: 1
                    }
                },
                State {
                    name: "enabled"
                    when: loginButton.enabled
                    PropertyChanges {
                        target: buttonBackground
                        opacity: 1
                    }
                    PropertyChanges {
                        target: buttonText
                        opacity: 1
                    }
                }
            ]

            transitions: Transition {
                PropertyAnimation {
                    properties: "color, opacity"
                    duration: 150
                }
            }

    onClicked: { 
    	loadCredentials(checkAndLogin);
    }
  }
 }
}
