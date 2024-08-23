import 'package:flutter/material.dart';

void main() {
  runApp(const MaterialApp(
    home: ChatAppBar(),
    debugShowCheckedModeBanner: false,
  ));
}

class ChatAppBar extends StatelessWidget  {
  const ChatAppBar({super.key});
 final bool isOnline = true;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.white,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: Colors.black),
          onPressed: () {
            Navigator.pop(context);
          },
        ),
        title:  Row(
          children: [
            Stack(
              children: [
                const CircleAvatar(
                  radius: 28,
                  backgroundImage: AssetImage(
                    'assets/avater.png',
                  ), // Replace with the correct image path
                ),

                // Add online status indicator here
                
            Positioned(
              bottom: 0,
              right: 0,
              top: 30,
              child: isOnline ? const Icon(Icons.circle, color: Colors.green, size: 10) :
                  const Icon( Icons.circle, color: Colors.grey, size: 10),
            ),

              ],
            ),
            const SizedBox(width: 10),
            const Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Sabila Sayma',
                  style: TextStyle(
                    color: Colors.black,
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                  ),
                ),
                Text(
                  '8 members, 5 online',
                  style: TextStyle(
                    color: Colors.grey,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.call_outlined, color: Colors.black),
            onPressed: () {
              // Add call action
            },
          ),
          IconButton(
            icon: const Icon(Icons.videocam_outlined, color: Colors.black),
            onPressed: () {
              // Add video call action
            },
          ),
        ],
      ),
      body: const SizedBox(),
    );
  }
}
