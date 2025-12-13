### EAC reversing
I have not done much EAC reversing but heres some major things i've discovered for different games. 
### Apex (steam version only)
#### note: this is probably not getting updated soon because i haven't worked on apex in around a year.

for some reason apex steam and apex on EA have different anticheats so this section is only from the steam version.
\
the main "ban" implementation is actually the serversided anticheat so you cant just hook requests to `https://partner.steam-api.com/ICheatReportingService/RequestPlayerGameBan/v1/`. (the client still calls it for some reason).

### ban flags
one of the biggest ban flags i've noticed is that if your headshot rate is above ~75% then you'll get kicked and most of the time banned. 


this is extremely easy to bypass by just targeting the lower neck instead of the head bone and it pervents getting 100% headshot rate. 


OR you can switch target bones.  


My smoothing implementation was actually super simple 
```cpp
if (settings::dynamic_aim) {
	static Point prevTarget{ -1.f, -1.f };
	static Point currentPos;
	static bool initialized = false;

	static std::default_random_engine rng(std::random_device{}());
	static std::uniform_real_distribution<float> microJitter(-1.0f, 1.0f);
	static std::uniform_real_distribution<float> speedVariation(0.8f, 1.2f);
	static std::uniform_int_distribution<int> pauseChance(0, 100);

	float centerX = Width * 0.5f;
	float centerY = Height * 0.5f;

	Point target{ static_cast<float>(x), static_cast<float>(y) };

	if (!initialized) {
		currentPos = { centerX, centerY };
		initialized = true;
	}

	if (std::hypot(target.x - prevTarget.x, target.y - prevTarget.y) > 5.0f) {
		prevTarget = target;
	}

	float dx = target.x - currentPos.x;
	float dy = target.y - currentPos.y;

	float dist = std::hypot(dx, dy);

	if (dist < 1.0f) {
		driver::mouse_move(microJitter(rng), microJitter(rng));
		return;
	}

	// randomly pause to simulate hesitation ~5% chance
	if (pauseChance(rng) < 5) {
		driver::mouse_move(microJitter(rng) * 0.5f, microJitter(rng) * 0.5f);
		return;
	}

	float dirX = dx / dist;
	float dirY = dy / dist;

	float baseSpeed = std::clamp(dist / 10.0f, 2.0f, 20.0f);
	float speed = baseSpeed * speedVariation(rng);
	float stepX = dirX * speed;
	float stepY = dirY * speed;

	// avoid straight line
	// perp vector: (-dirY, dirX)
	float jitterAmount = std::clamp(dist / 30.0f, 0.3f, 1.5f);
	float jitterX = -dirY * microJitter(rng) * jitterAmount;
	float jitterY = dirX * microJitter(rng) * jitterAmount;

	stepX += jitterX;
	stepY += jitterY;

	if (std::hypot(stepX, stepY) > dist) {
		stepX = dx;
		stepY = dy;
	}
  // uses mouse service callback to move mouse. https://github.com/moonlightrblx/reversing/blob/main/utils/kernelmouse.md for more info
	driver::mouse_move(stepX, stepY);

	currentPos.x += stepX;
	currentPos.y += stepY;
}
```
