/* ===================================================
 * main.js
 * ===================================================
 * Copyright 2016 PrettyGoodPasswords
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================== */
 
var isLoggedIn = false;
var check_logged_in_interval = null;
var idleLogoutSeconds = 30;

function ajax_load(url) {

    var elemToFade = 'main';
    var elemToReplace = 'main';

    var fadeElem = $("#" + elemToFade);

    var transition = true;

    var show_wait = false;

    if(url == "/list")
    {
        show_wait = true;
    }

    if(transition)
    {
        fadeElem.fadeOut( 100, function()
        {
            if(show_wait)
                show_wait_indicator()

                var xhttp = new XMLHttpRequest();
              xhttp.onreadystatechange = function() {
                if (xhttp.readyState == 4 && xhttp.status == 200) {

                    domElemToReplace = document.getElementById(elemToReplace);

                    if(domElemToReplace)
                            domElemToReplace.innerHTML = xhttp.responseText;

                  hide_wait_indicator();
                  fadeElem.fadeIn( 200);
                }
              };

              xhttp.open("GET", url, true);
              xhttp.send();

        });
    }
    else
    {
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
            if (xhttp.readyState == 4 && xhttp.status == 200)
            {

                domElemToReplace = document.getElementById(elemToReplace);

                if(domElemToReplace)
                        domElemToReplace.innerHTML = xhttp.responseText;
            }
        };

        xhttp.open("GET", url, true);
        xhttp.send();
    }



  //for a few specific urls, we want to modify or check our isLoggedIn.
  if(url == '/end' || url == '/clean')
  {
    isLoggedIn = false;
    logged_out_navbar();
  }
}

function ajax_post(url, form_data, elemToFade, elemToReplace, on_post_cb)
{
    var fadeElem = $("#" + elemToFade);

    var transition = true;

    var show_wait = false;

    if(url == "/check_master" ||url == "/init_master" || url == "/change_master"  || url == "/search")
    {
        show_wait = true;
    }

    if(transition)
    {
        fadeElem.fadeOut( 100, function()
        {
            if(show_wait)
                show_wait_indicator();

            var xhttp = new XMLHttpRequest();

            xhttp.onreadystatechange = function() {
                if (xhttp.readyState == 4 && xhttp.status == 200) {

                    //$("#progress").fadeOut(200);
                    hide_wait_indicator();

                    if(on_post_cb != null)
                    {
                        on_post_cb(xhttp.responseText);
                    }
                    else
                    {
                        fadeElem.fadeIn( 200 );

                        var domElemToReplace = document.getElementById(elemToReplace);

                        if(domElemToReplace)
                            domElemToReplace.innerHTML = xhttp.responseText;
                    }
                }
            };

            xhttp.open("POST", url, true);

            xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

            xhttp.send(form_data);
        });
    }
    else
    {
        var xhttp = new XMLHttpRequest();

        xhttp.onreadystatechange = function() {
            if (xhttp.readyState == 4 && xhttp.status == 200) {

                //$("#progress").fadeOut(200);

                if(on_post_cb != null)
                {
                    on_post_cb(xhttp.responseText);
                }
                else
                {
                    var domElemToReplace = document.getElementById(elemToReplace);

                    if(domElemToReplace)
                        domElemToReplace.innerHTML = xhttp.responseText;
                }
            }
        };

        xhttp.open("POST", url, true);

        xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

        xhttp.send(form_data);
    }


}

function logged_in_navbar()
{
    var navbar_logged_in = document.getElementById("navbar_logged_in");
    var navbar_logged_out = document.getElementById("navbar_logged_out");
    var transition = true;

    if(transition)
    {
        $(navbar_logged_out).fadeOut(200, function()
        {
            $(navbar_logged_in).fadeIn(200);

            navbar_logged_out.style.display ="none";
        })
    }
    else
    {
        navbar_logged_in.style.display ="block";
        navbar_logged_out.style.display ="none";
    }

}

function logged_out_navbar()
{
    var navbar_logged_in = document.getElementById("navbar_logged_in");
    var navbar_logged_out = document.getElementById("navbar_logged_out");
    var transition = false;

    if(transition)
    {
        $(navbar_logged_in).fadeOut(200, function()
        {
            $(navbar_logged_out).fadeIn(200);

            navbar_logged_in.style.display ="none";
        })
    }
    else
    {
        navbar_logged_in.style.display ="none";
        navbar_logged_out.style.display ="block";
    }
}

function generate_password(elem_id)
{
    var password_field = document.getElementById(elem_id);

    if(password_field)
    {
        var charset = "";
        charset += "0123456789";
        charset += "abcdefghijklmnopqrstuvwxyz";
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        charset += "!#$%&*+-:=^_~";
        var length = 12;
        var password = "";

        for (var i = 0; i < length; i++)
				password += charset.charAt(randomInt(charset.length));
        password_field.value = password;
    }
}

// Returns a random integer in the range [0, n) using a variety of methods
function randomInt(n) {
	var x = randomIntMathRandom(n);
	x = (x + randomIntBrowserCrypto(n)) % n;
	return x;
}

// Not secure or high quality, but always available
function randomIntMathRandom(n) {
	var x = Math.floor(Math.random() * n);
	if (x < 0 || x >= n)
		throw "Arithmetic exception";
	return x;
}

// Uses a secure, unpredictable random number generator if available; otherwise returns 0
function randomIntBrowserCrypto(n) {
	if (typeof Uint32Array == "function" && "crypto" in window && "getRandomValues" in window.crypto) {
		// Generate an unbiased sample
		var x = new Uint32Array(1);
		do window.crypto.getRandomValues(x);
		while (x[0] - x[0] % n > 4294967296 - n);
		return x[0] % n;
	} else
		return 0;
}

function ajax_form(_url, formId) 
{
    url = _url + '?' + $(formId).serialize()
    ajax_load(url);
} 

function ajax_post_form(_url, formId, elemToFade, elemToReplace, on_post_cb)
{
    ajax_post(_url, $(formId).serialize(), elemToFade, elemToReplace, on_post_cb);
}

function on_main_init()
{
    hide_wait_indicator();

    ajax_load("/master");

    //in case we are already logged in, we will post a background check
    //to refresh the correct navbar.
    check_logged_in_interval = setInterval(refresh_is_logged_in, 500); // 1/2 second
}

function submit_master_pass()
{
    ajax_post_form("/check_master", "#enterMasterPass", "main", "main", on_master_pass_reply);
}

function init_master_pass()
{
    ajax_post_form("/init_master", "#initMasterPass", "main", "main", on_master_pass_reply);
}

function change_master_pass()
{
    ajax_post_form("/change_master", "#changeMasterPass", "main", "main", on_master_pass_reply);
}

function on_master_pass_reply(url)
{
    ajax_load(url);

    isLoggedIn = (url == "/list");

    if(isLoggedIn)
    {
        logged_in_navbar();
    }
    else
    {
        logged_out_navbar();
    }
}

function test_pass_strength(formElem)
{
    ajax_post_form("/password_strength", formElem, "strength_meter", "strength_meter", on_pass_meter);
}

function on_pass_meter(reply)
{
    $("#strength_meter").fadeIn(200);

    document.getElementById("strength_meter").innerHTML = reply;

    var slider = document.getElementById("mobile-slider");

    if(slider != null)
    {
        //this is on jquery mobile only
        //we are going to read the value from the input slider
        var slider_val = slider.valueAsNumber;

        //the input slider was a carrier for the value only. remove it from the dom.
        $(slider).remove();

        //now we are dynamically creating a progress bar using this jquery mobile
        //plugin. https://github.com/tolis-e/jQuery-Mobile-Progress-Bar-with-Percentage
        var pbar = null;

        if(typeof jQMProgressBar !== 'undefined')
        {
            pbar = jQMProgressBar('progressbar')
                            .setOuterTheme('c')
                            .setInnerTheme('d')
                            .isMini(true)
                            .showCounter(false)
                            .setMax(100)
                            .build();

            //set the bar to the end value.
            pbar.setValue(slider_val);
        }

        //look for the dom element so we can set the background color.
        var activeBar = document.getElementById("progressbar");

        if(activeBar)
        {
            //I wish I could have set the css class instead. didn't work.
            var bgColor = "#900C3F";
            var terribleIcon = '<a id="strength_icon" href="#how_strong" class="ui-btn ui-mini ui-icon-forbidden ui-btn-icon-left">Terrible</a>';
            var weakIcon = '<a id="strength_icon" href="#how_strong" class="ui-btn ui-mini ui-icon-alert ui-btn-icon-left">Weak</a>';
            var okIcon = '<a id="strength_icon" href="#how_strong" class="ui-btn ui-mini ui-icon-check ui-btn-icon-left">Moderate</a>';
            var strongIcon = '<a id="strength_icon" href="#how_strong" class="ui-btn ui-mini ui-icon-star ui-btn-icon-left">Strong</a>';
            var iconDomElem = document.getElementById("strength_icon");

            if(slider_val > 49)
            {
                bgColor = "#55f940";

                if(iconDomElem)
                    iconDomElem.innerHTML = strongIcon;
            }
            else if(slider_val > 29)
            {
                bgColor = "#d5f940";
                if(iconDomElem)
                    iconDomElem.innerHTML = okIcon;
            }
            else if(slider_val > 10)
            {
                bgColor = "#F9C040";
                if(iconDomElem)
                    iconDomElem.innerHTML = weakIcon;
            }
            else
            {
                if(iconDomElem)
                    iconDomElem.innerHTML = terribleIcon;
            }

            var children = activeBar.childNodes;

            for(var i = 0; i < children.length; i++)
            {
                var child = children[i];

                child.style.background = bgColor;
            }
        }

    }
}

function edit_entry(key)
{
    url = "/edit?key=" + key;
    ajax_load(url);
}

function search_list()
{
    ajax_post_form("/search", "#search_form", "main", "main", null);
}

function submit_create_form()
{
    ajax_post_form("/update", "#createForm", "main", "main", null);
}

function submit_edit_entry_form()
{
    ajax_post_form("/update", "#editEntryForm", "main", "main", null);
}

function refresh_is_logged_in()
{
    if(check_logged_in_interval == null)
        return;

    clearInterval(check_logged_in_interval);
    check_logged_in_interval = null;

    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (xhttp.readyState == 4 && xhttp.status == 200) 
        {
            isLoggedIn = (xhttp.responseText == "1");

            if(isLoggedIn)
            {
                logged_in_navbar();
            }
            else
            {
                logged_out_navbar();
            }
        }
    };
    xhttp.open("GET", "/is_logged_in", true);
    xhttp.send();
}

function hide_wait_indicator()
{
    var elem = document.getElementById("wait_indicator");

    if(elem)
        elem.style.display ="none";
}

function show_wait_indicator()
{
    var elem = document.getElementById("wait_indicator");

    if(elem)
        elem.style.display ="block";
}